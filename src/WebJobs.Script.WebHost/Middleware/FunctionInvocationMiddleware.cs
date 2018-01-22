// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
using System;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Logging;
using Microsoft.Azure.WebJobs.Script.Description;
using Microsoft.Azure.WebJobs.Script.Extensions;
using Microsoft.Azure.WebJobs.Script.WebHost.Features;
using Microsoft.Azure.WebJobs.Script.WebHost.Security.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.Azure.WebJobs.Script.WebHost.Middleware
{
    public class FunctionInvocationMiddleware
    {
        private readonly RequestDelegate _next;

        public FunctionInvocationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public static bool IsHomepageDisabled
        {
            get
            {
                return string.Equals(Environment.GetEnvironmentVariable(EnvironmentSettingNames.AzureWebJobsDisableHomepage),
                    bool.TrueString, StringComparison.OrdinalIgnoreCase);
            }
        }

        public async Task Invoke(HttpContext context, WebScriptHostManager manager)
        {
            // flow required context through the request pipeline
            // downstream middleware and filters rely on this
            context.Items.Add(ScriptConstants.AzureFunctionsHostManagerKey, manager);
            SetRequestId(context.Request);
            if (_next != null)
            {
                await _next(context);
            }

            IFunctionExecutionFeature functionExecution = context.Features.Get<IFunctionExecutionFeature>();

            object nestedProxies;
            context.Items.TryGetValue("X_MS_NestedProxyCount", out nestedProxies);

            //HttpBufferingService is disabled for non - proxy functions.
            if (functionExecution != null && !functionExecution.Descriptor.Metadata.IsProxy && nestedProxies == null)
            {
                    var bufferingFeature = context.Features.Get<IHttpBufferingFeature>();
                    bufferingFeature?.DisableRequestBuffering();
                    bufferingFeature?.DisableResponseBuffering();
            }

            IActionResult result = null;

            if (functionExecution != null && !context.Response.HasStarted)
            {
                result = await GetResultAsync(context, functionExecution);

                // TODO: need some cleanup
                if (nestedProxies != null && int.Parse(nestedProxies.ToString()) > 0)
                {
                    context.Items.Add("X_MS_ProxyResult", result);

                    context.Items["X_MS_NestedProxyCount"] = int.Parse(nestedProxies.ToString()) - 1;
                    return;
                }
            }
            else if (functionExecution == null
                && context.Request.Path.Value == "/"
                && !context.Response.HasStarted)
            {
                if (IsHomepageDisabled)
                {
                    result = new NoContentResult();
                }
                else
                {
                    result = new ContentResult()
                    {
                        Content = GetHomepage(),
                        ContentType = "text/html",
                        StatusCode = 200
                    };
                }
            }

            if (result != null && !context.Response.HasStarted)
            {
                var actionContext = new ActionContext
                {
                    HttpContext = context
                };

                await result.ExecuteResultAsync(actionContext);
            }
        }

        private async Task<IActionResult> GetResultAsync(HttpContext context, IFunctionExecutionFeature functionExecution)
        {
            if (functionExecution.Descriptor == null)
            {
                return new NotFoundResult();
            }

            if (context.Request.IsColdStart())
            {
                // for cold start requests we want to measure the request
                // pipeline dispatch time
                // important that this stopwatch is started as early as possible
                // in the pipeline (in this case, in our first middleware)
                var sw = new Stopwatch();
                sw.Start();
                context.Request.HttpContext.Items.Add(ScriptConstants.AzureFunctionsColdStartKey, sw);
            }

            // Add route data to request info
            // TODO: Keeping this here for now as other code depend on this property, but this can be done in the HTTP binding.
            var routingFeature = context.Features.Get<IRoutingFeature>();
            context.Items.Add(HttpExtensionConstants.AzureWebJobsHttpRouteDataKey, new Dictionary<string, object>(routingFeature.RouteData.Values));

            bool authorized = await AuthenticateAndAuthorizeAsync(context, functionExecution.Descriptor);
            if (!authorized)
            {
                return new UnauthorizedResult();
            }

            // If the function is disabled, return 'NotFound', unless the request is being made with Admin credentials
            if (functionExecution.Descriptor.Metadata.IsDisabled &&
                !AuthUtility.PrincipalHasAuthLevelClaim(context.User, AuthorizationLevel.Admin))
            {
                return new NotFoundResult();
            }

            if (functionExecution.CanExecute)
            {
                // Add the request to the logging scope. This allows the App Insights logger to
                // record details about the request.
                ILoggerFactory loggerFactory = context.RequestServices.GetService<ILoggerFactory>();
                ILogger logger = loggerFactory.CreateLogger(LogCategories.CreateFunctionCategory(functionExecution.Descriptor.Name));
                var scopeState = new Dictionary<string, object>()
                {
                    [ScriptConstants.LoggerHttpRequest] = context.Request,
                };

                using (logger.BeginScope(scopeState))
                {
                    // TODO: Flow cancellation token from caller
                    await functionExecution.ExecuteAsync(context.Request, CancellationToken.None);
                }
            }

            if (context.Items.TryGetValue(ScriptConstants.AzureFunctionsHttpResponseKey, out object result) && result is IActionResult actionResult)
            {
                return actionResult;
            }

            return new OkResult();
        }

        private async Task<bool> AuthenticateAndAuthorizeAsync(HttpContext context, FunctionDescriptor descriptor)
        {
            var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();
            AuthorizationPolicy policy = AuthUtility.CreateFunctionPolicy();

            // Authenticate the request
            var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);

            // Authorize using the function policy and resource
            var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult, context, descriptor);

            return authorizeResult.Succeeded;
        }

        internal static void SetRequestId(HttpRequest request)
        {
            string requestID = request.GetHeaderValueOrDefault(ScriptConstants.AntaresLogIdHeaderName) ?? Guid.NewGuid().ToString();
            request.HttpContext.Items[ScriptConstants.AzureFunctionsRequestIdKey] = requestID;
        }
        private string GetHomepage()
        {
            var assembly = typeof(FunctionInvocationMiddleware).Assembly;
            using (Stream resource = assembly.GetManifestResourceStream(assembly.GetName().Name + ".Home.html"))
            using (var reader = new StreamReader(resource))
            {
                return reader.ReadToEnd();
            }
        }
    }
}

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Routing;

namespace OpenTOY.Emails.Services;

public interface IRazorViewToStringRenderer
{
    Task<string> RenderViewToStringAsync<TModel>(string viewName, TModel model);
}

public class RazorViewToStringRenderer : IRazorViewToStringRenderer
{
    private readonly IRazorViewEngine _viewEngine;

    private readonly ITempDataProvider _tempDataProvider;

    private readonly IServiceProvider _serviceProvider;

    public RazorViewToStringRenderer(IRazorViewEngine viewEngine, ITempDataProvider tempDataProvider,
        IServiceProvider serviceProvider)
    {
        _viewEngine = viewEngine;
        _tempDataProvider = tempDataProvider;
        _serviceProvider = serviceProvider;
    }

    public async Task<string> RenderViewToStringAsync<TModel>(string viewName, TModel model)
    {
        var actionContext = GetActionContext();
        var view = FindView(actionContext, viewName);

        await using var output = new StringWriter();
        var viewData = new ViewDataDictionary<TModel>(new EmptyModelMetadataProvider(), new ModelStateDictionary())
        {
            Model = model
        };

        var tempData = new TempDataDictionary(actionContext.HttpContext, _tempDataProvider);
        var viewContext = new ViewContext(actionContext, view, viewData, tempData, output, new HtmlHelperOptions());

        await view.RenderAsync(viewContext);
        return output.ToString();
    }

    private ActionContext GetActionContext()
    {
        var httpContext = new DefaultHttpContext
        {
            RequestServices = _serviceProvider
        };

        return new ActionContext(httpContext, new RouteData(), new ActionDescriptor());
    }

    private IView FindView(ActionContext actionContext, string viewName)
    {
        var getViewResult = _viewEngine.GetView(null, viewName, true);
        if (getViewResult.Success)
        {
            return getViewResult.View;
        }

        var findViewResult = _viewEngine.FindView(actionContext, viewName, true);
        if (findViewResult.Success)
        {
            return findViewResult.View;
        }

        var searchedLocations = getViewResult.SearchedLocations.Concat(findViewResult.SearchedLocations);
        var errorMessage = $"Unable to find view '{viewName}'. The following locations were searched:\n{string.Join(Environment.NewLine, searchedLocations)}";
        throw new InvalidOperationException(errorMessage);
    }
}
using API_Common.Exceptions.Models;
using Microsoft.AspNetCore.Mvc;

namespace API_Common.Exceptions;

public class ExceptionHandler
{
    private readonly ILogger<ExceptionHandler> _logger;

    public ExceptionHandler(ILogger<ExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async Task<IActionResult> HandleExceptionAsync(string controllerName, string methodName, Func<Task<IActionResult>> function)
    {
        try
        {
            return await function();
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Exception handled - {Controller} - {Method}", controllerName, methodName);
            
            return new ObjectResult(new { Code = ErrorEnum.GeneralError, Message = nameof(ErrorEnum.GeneralError) }) { StatusCode = 500};
        }
    }
}
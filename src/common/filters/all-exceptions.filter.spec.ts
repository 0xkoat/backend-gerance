import { ArgumentsHost, ForbiddenException, Logger } from '@nestjs/common';
import { AllExceptionsFilter } from './all-exceptions.filter';

describe('AllExceptionsFilter', () => {
  let filter: AllExceptionsFilter;
  let mockResponse: { status: jest.Mock; json: jest.Mock };
  let mockRequest: { method: string; originalUrl: string; user?: unknown };
  let host: ArgumentsHost;

  beforeEach(() => {
    filter = new AllExceptionsFilter();
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    mockRequest = { method: 'GET', originalUrl: '/api/vm/assets' };

    host = {
      switchToHttp: () => ({
        getResponse: () => mockResponse,
        getRequest: () => mockRequest,
      }),
    } as unknown as ArgumentsHost;
  });

  it('returns the HttpException status and body unchanged', () => {
    const debugSpy = jest.spyOn(Logger.prototype, 'debug').mockImplementation();
    const exception = new ForbiddenException('not allowed');

    filter.catch(exception, host);

    expect(mockResponse.status).toHaveBeenCalledWith(403);
    expect(mockResponse.json).toHaveBeenCalledWith(exception.getResponse());
    debugSpy.mockRestore();
  });

  it('logs a 5xx HttpException at error level with a stack trace', () => {
    const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const exception = new Error('database connection lost');

    filter.catch(exception, host);

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('GET /api/vm/assets'),
      exception.stack,
    );
    errorSpy.mockRestore();
  });

  it('does not log a 4xx HttpException at error level', () => {
    const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const debugSpy = jest.spyOn(Logger.prototype, 'debug').mockImplementation();

    filter.catch(new ForbiddenException('not allowed'), host);

    expect(errorSpy).not.toHaveBeenCalled();
    expect(debugSpy).toHaveBeenCalledWith(
      expect.stringContaining('GET /api/vm/assets'),
    );
    errorSpy.mockRestore();
    debugSpy.mockRestore();
  });

  it('converts a non-HttpException thrown value into a 500 with a generic body', () => {
    const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const exception = new Error('unexpected failure');

    filter.catch(exception, host);

    expect(mockResponse.status).toHaveBeenCalledWith(500);
    expect(mockResponse.json).toHaveBeenCalledWith({
      statusCode: 500,
      message: 'Internal server error',
    });
    errorSpy.mockRestore();
  });

  it('includes tenantId and userId in the logged context when the caller is authenticated', () => {
    const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    mockRequest.user = { userId: 'user-1', tenantId: 'tenant-1' };

    filter.catch(new Error('boom'), host);

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('tenantId=tenant-1 userId=user-1'),
      expect.anything(),
    );
    errorSpy.mockRestore();
  });

  it('falls back to n/a for tenantId/userId when the caller is not authenticated', () => {
    const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation();

    filter.catch(new Error('boom'), host);

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('tenantId=n/a userId=n/a'),
      expect.anything(),
    );
    errorSpy.mockRestore();
  });
});

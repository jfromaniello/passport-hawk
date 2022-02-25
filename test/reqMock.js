exports.buildRequest = function buildRequest(reqProps) {
    const obj = Object.create({ headers: reqProps.headers });
  
    return Object.assign(obj, {
      method: reqProps.method,
      url: reqProps.url,
      originalUrl: reqProps.originalUrl,
    });
  };
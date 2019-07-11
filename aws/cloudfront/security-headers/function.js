'use strict';
exports.handler = (event, context, callback) => {

    //Get contents of response
    const response = event.Records[0].cf.response;
    const headers = response.headers;

    //Set new headers
    headers['strict-transport-security'] = [{key: 'Strict-Transport-Security',
                                            value: 'max-age=604800'}];
    // STS expiration is currently set for one week for testing. We should
    // eventually bump this up to at least one year, and maybe also add the
    // "includeSubdomains" and "preload" directives. Both of these options
    // should be carefully considered before implementing though.
    // Links to helpful resources:
    // https://tools.ietf.org/html/rfc6797#page-28
    // https://hstspreload.org/

    //Return modified response
    callback(null, response);
};

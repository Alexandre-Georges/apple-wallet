var http = require('http');
var url = require('url');

var config = require('./config.js');
var signature = require('./signature.js');

config.addValue(config.keys.PORT, parseInt(process.argv[2]) || 8080);

config.addValue(config.keys.CERTIFICATE_PASSWORD, process.argv[3] || 'password');
config.addValue(config.keys.CERTIFICATES_DIR, process.argv[4] || 'certificates');
config.addValue(config.keys.APPLE_CERTIFICATE_PEM, config.getValue(config.keys.CERTIFICATES_DIR) + '/AWDRCA.pem');
config.addValue(config.keys.PASS_CERTIFICATE_P12, config.getValue(config.keys.CERTIFICATES_DIR) + '/pass-certificate-key.p12');
config.addValue(config.keys.PASS_CERTIFICATE_PEM, config.getValue(config.keys.CERTIFICATES_DIR) + '/pass-certificate.pem');
config.addValue(config.keys.PASS_KEY_PEM, config.getValue(config.keys.CERTIFICATES_DIR) + '/pass-key.pem');

config.addValue(config.keys.SOURCES_DIR, process.argv[5] || 'sources');
config.addValue(config.keys.PASS_TEMPLATE, process.argv[6] || './template/pass.json');

function processError (error, response) {
    if (error !== null) {
        var errorMessage = error.message;
        console.log('Error: ' + errorMessage);

        response.writeHead(500, {
            'Content-Length': errorMessage.length,
            'Content-Type': 'text/plain'
        });
        response.write(errorMessage);
        response.end();
    }
}

signature.init(function () {
    startServer();
});

function startServer() {
    var server = http.createServer(handleRequest);

    server.listen(config.getValue(config.keys.PORT), function(){
        console.log('Server started on port ' + config.getValue(config.keys.PORT));
    });
}

function generatePolicyNumber() {
    var highest = 999999999;
    var policyNumber = Math.floor(Math.random() * highest).toString();
    while (policyNumber.length < 12) {
        policyNumber = '0' + policyNumber;
    }
    return 'FG' + policyNumber;
}

function handleRequest(request, response) {

    var errorDuringGeneration = function (error) {
        processError(error, response);
    };

    try {
        var queryObject = url.parse(request.url, true).query;

        if (!queryObject.firstName || !queryObject.lastName || !queryObject.startDate || !queryObject.endDate) {
            processError('Incorrect parameters: ' + JSON.stringify(queryObject), response);
        } else {

            signature.gatherFiles(function (files) {
                signature.addPass(files, {
                    POLICY_NUMBER: generatePolicyNumber(),
                    FIRST_NAME: queryObject.firstName,
                    LAST_NAME: queryObject.lastName,
                    START_DATE: queryObject.startDate,
                    END_DATE: queryObject.endDate
                }, function (files) {
                    try {
                        var manifestContent = signature.generateManifest(files);
                        var filesWithManifest = signature.addManifest(manifestContent, files);
                        signature.signManifest(manifestContent, filesWithManifest, function (files) {
                            try {
                                response.setHeader('Content-Type', 'application/vnd.apple.pkpass');
                                response.setHeader('Content-disposition', 'attachment; filename=pass.pkpass');

                                signature.generatePass(files, response, function () {
                                    try {
                                        response.statusCode = 200;
                                        response.end();
                                    } catch (exception) {
                                        processError(exception, response);
                                    }
                                }, errorDuringGeneration);

                            } catch (exception) {
                                processError(exception, response);
                            }
                        }, errorDuringGeneration);

                    } catch (exception) {
                        processError(exception, response);
                    }
                }, errorDuringGeneration);
            }, errorDuringGeneration);
        }
    } catch (exception) {
        processError(exception, response);
    }
};

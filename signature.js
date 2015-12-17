var archiver = require('archiver');
var child_process = require('child_process');
var crypto = require('crypto');
var fs = require('fs');
var config = require('./config.js');

Signature = {

    init : function (callback) {
        var self = this;
        this.generateCertificate(function () {
            self.generateKey(function () {
                callback();
            });
        });
    },

    generateCertificate : function (callback) {

        var self = this;

        var args = [
            'pkcs12',
            '-nodes',
            '-clcerts',
            '-nokeys',
            '-in', config.getValue(config.keys.PASS_CERTIFICATE_P12),
            '-out', config.getValue(config.keys.PASS_CERTIFICATE_PEM),
            '-passin', 'pass:' + config.getValue(config.keys.CERTIFICATE_PASSWORD)
        ];

        child_process.execFile('openssl', args, function (error, stdout, stderr) {
            self.processResult(error, stdout, stderr);
            callback();
        });
    },

    generateKey : function (callback) {

        var self = this;

        var args = [
            'pkcs12',
            '-nodes',
            '-nocerts',
            '-in', config.getValue(config.keys.PASS_CERTIFICATE_P12),
            '-out', config.getValue(config.keys.PASS_KEY_PEM),
            '-passin', 'pass:' + config.getValue(config.keys.CERTIFICATE_PASSWORD),
            '-passout', 'pass:' + config.getValue(config.keys.CERTIFICATE_PASSWORD)
        ];

        child_process.execFile('openssl', args, function (error, stdout, stderr) {
            self.processResult(error, stdout, stderr);
            callback();
        });

    },

    gatherFiles : function (callback, errorCallback) {

        try {
            var self = this;
            var filesResult = [];

            fs.readdir(config.getValue(config.keys.SOURCES_DIR), function (error, files) {
                try {
                    if (error) {
                        errorCallback(error);
                    } else {
                        for (var fileIndex in files) {
                            var fileName = files[fileIndex];
                            self.readFile(fileName, filesResult, files.length, callback);
                        }
                    }
                } catch (exception) {
                    errorCallback(exception);
                }
            });

        } catch (exception) {
            errorCallback(exception);
        }
    },

    readFile : function (fileName, files, expectedNumberOfFiles, callback) {

        var self = this;

        fs.readFile(config.getValue(config.keys.SOURCES_DIR) + '/' + fileName, function (error, content) {

            self.processError(error);

            files.push({
                name : fileName,
                content : content
            });

            if (files.length === expectedNumberOfFiles) {
                callback(files);
            }
        });
    },

    addPass : function (files, tokens, callback, errorCallback) {
        try {
            var self = this;
            var passTemplate = config.getValue(config.keys.PASS_TEMPLATE);

            fs.readFile(passTemplate, config.ENCODING, function (error, content) {
                try {
                    if (error) {
                        errorCallback(error);
                    } else {
                        var passContent = self.replaceTokens(content, tokens);

                        files.push({
                            name : 'pass.json',
                            content : passContent
                        });

                        callback(files);
                    }
                } catch (exception) {
                    errorCallback(exception);
                }
            });
        } catch (exception) {
            errorCallback(exception);
        }
    },

    replaceTokens : function (fileContent, tokens) {
        var result = fileContent;
        for (var tokenKey in tokens) {
            result = result.replace(tokenKey, tokens[tokenKey], 'g');
        }
        return result;
    },

    generateManifest : function (files) {

        var manifest_content = '{';

        for (var fileIndex in files) {
            var file = files[fileIndex];
            var shasum = crypto.createHash('sha1');
            shasum.update(file.content, 'binary');
            manifest_content += '\n\t"' + file.name + '" : "' + shasum.digest('hex') + '",';
        }

        manifest_content += '\n}';

        return manifest_content;
    },

    addManifest: function (manifestContent, files) {

        files.push({
            name : 'manifest.json',
            content : manifestContent
        });

        return files;
    },

    signManifest : function (manifestContent, files, callback, errorCallback) {
        try {
            var args = [
                'smime',
                '-sign',
                '-binary',
                '-signer', config.getValue(config.keys.PASS_CERTIFICATE_PEM),
                '-certfile', config.getValue(config.keys.APPLE_CERTIFICATE_PEM),
                '-inkey', config.getValue(config.keys.PASS_KEY_PEM),
                '-passin', 'pass:' + config.getValue(config.keys.CERTIFICATE_PASSWORD)
            ];

            var sign = child_process.execFile('openssl', args, { stdio: 'pipe' }, function (error, stdout, stderr) {
                try {
                    if (error) {
                        errorCallback(error);
                    } else {
                        var signature = stdout.split(/\n\n/)[3];
                        files.push({
                            name : 'signature',
                            content : new Buffer(signature, "base64")
                        });

                        callback(files);
                    }
                } catch (exception) {
                    errorCallback(exception);
                }
            });
            sign.stdin.write(manifestContent);
            sign.stdin.end();

        } catch (exception) {
            errorCallback(exception);
        }
    },

    generatePass : function (files, outputStream, callback, errorCallback) {

        try {
            var archive = archiver('zip', { store : true });

            archive.on('error', function (error) {
                errorCallback(error);
            });
            archive.on('end', function () {
                callback();
            });
            archive.pipe(outputStream);

            for (var fileIndex in files) {
                var file = files[fileIndex];
                archive.append(file.content, { name : file.name });
            }

            archive.finalize();

        } catch (exception) {
            errorCallback(exception);
        }
    },

    processError : function (error) {
        if (error !== null) {
            console.log('Error: ' + error);
            process.exit(1);
        }
    },

    processResult : function (error, stdout, stderr) {
        console.log('stdout: ' + stdout);
        console.log('stderr: ' + stderr);
        this.processError(error);
    }
};

module.exports = Signature;
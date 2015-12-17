Config = {
    ENCODING : 'utf8',
    keys : {
        APPLE_CERTIFICATE_PEM : 'APPLE_CERTIFICATE_PEM',
        CERTIFICATE_PASSWORD : 'CERTIFICATE_PASSWORD',
        CERTIFICATES_DIR : 'CERTIFICATES_DIR',
        PASS_TEMPLATE : 'PASS_TEMPLATE',
        PORT : 'PORT',
        PASS_CERTIFICATE_P12 : 'PASS_CERTIFICATE_P12',
        PASS_CERTIFICATE_PEM : 'PASS_CERTIFICATE_PEM',
        PASS_KEY_PEM : 'PASS_KEY_PEM',
        SOURCES_DIR : 'SOURCES_DIR'
    },
    values: [],
    addValue: function (key, value) {
        Config.values[key] = value;
    },
    getValue: function (key) {
        return Config.values[key];
    }
};

module.exports = Config;
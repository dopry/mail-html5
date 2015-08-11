'use strict';

var ngModule = angular.module('woServices');
ngModule.service('newsletter', Newsletter);
module.exports = Newsletter;

function Newsletter() {}

/**
 * Sign up to the newsletter
 */
Newsletter.prototype.signup = function(emailAddress, agree, appConfig) {
    return new Promise(function(resolve, reject) {
        // validate email address
        if (emailAddress.indexOf('@') < 0) {
            reject(new Error('Invalid email address!'));
            return;
        }

        if (!agree) {
            // don't sign up if the user has not agreed
            resolve(false);
            return;
        }

        var formData = new FormData();
        formData.append('EMAIL', emailAddress);
        formData.append('b_' + appConfig.mailChimpApiKey, '');

        var uri = appConfig.mailChimpEndPoint + '/subscribe/post' +
                      '?u=' + appConfig.mailChimpApiKey +
                      '&id=' + appConfig.mailChimpListId;
        var xhr = new XMLHttpRequest();
        xhr.open('post', uri, true);

        xhr.onload = function() {
            resolve(xhr);
        };

        xhr.onerror = function(err) {
            reject(err);
        };

        xhr.send(formData);
    });
};

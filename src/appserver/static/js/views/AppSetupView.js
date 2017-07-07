require.config({
    paths: {
        text: "../app/website_input/js/lib/text",
        setup_view: '../app/website_input/js/views/SetupView'
    }
});

define([
    "underscore",
    "jquery",
    "models/SplunkDBase",
    "setup_view",
    "util/splunkd_utils",
    "text!../app/website_input/js/templates/AppSetupView.html",
    "css!../app/website_input/css/AppSetupView.css"
], function(
    _,
    $,
    SplunkDBaseModel,
    SetupView,
    splunkd_utils,
    Template
){

    var WebsiteInputConfiguration = SplunkDBaseModel.extend({
	    initialize: function() {
	    	SplunkDBaseModel.prototype.initialize.apply(this, arguments);
	    }
	});

    return SetupView.extend({
        className: "AppSetupView",

        events: {
            "click #save-config" : "saveConfig"
        },

        defaults: {
            "secure_storage_realm" : "website_input_app_proxy",
            "secure_storage_username" : "IN_CONF_FILE"
        },

        formProperties: {
            'proxyServer' : '.proxy-address input',
            'proxyUser' : '.proxy-user input',
            'proxyServerPort' : '.proxy-port input',
            'proxyPassword' : '.proxy-password input',
            'proxyPasswordConfirmation' : '.proxy-password-confirm input',
            'proxyType' : '.proxy-type select'
        },

        initialize: function() {
        	this.options = _.extend({}, this.defaults, this.options);
            SetupView.prototype.initialize.apply(this, [this.options]);

            this.setupValidators();

            this.website_input_configuration = null;
            this.secure_storage_stanza = this.makeStorageEndpointStanza(this.options.secure_storage_username, this.options.secure_storage_realm);
        },

        updateModel: function(){
            this.website_input_configuration.entry.content.attributes.proxy_server = this.getProxyServer();
            this.website_input_configuration.entry.content.attributes.proxy_port = this.getProxyServerPort();
            this.website_input_configuration.entry.content.attributes.proxy_type = this.getProxyType();

            this.website_input_configuration.entry.content.attributes.proxy_user = this.getProxyUser();
            this.website_input_configuration.entry.content.attributes.proxy_password = ""; //This will be stored in secure storage; this.getProxyPassword();
        },

        savePassword: function(){
            var password = this.getProxyPassword();

            // Delete the secured password if the password was cleared
            if(password.length === 0){
                return this.deleteEncryptedCredential(this.secure_storage_stanza, true);
            }
            // Otherwise, update it
            else{
                return this.saveEncryptedCredential(this.options.secure_storage_username, password, this.options.secure_storage_realm);
            }
        },

        saveConfig: function(){

            if(!this.userHasAdminAllObjects()){
                alert("You don't have permission to edit this app");
            }
            else if(this.validate()){
                // Update the model with the latest info so that we can save it
                this.updateModel();

                this.showFormInProgress(true);

                $.when(
                    this.website_input_configuration.save(),
                    this.savePassword()
                )
                // If successful, show a success message
                .then(
                    function(){
                        this.showInfoMessage("Configuration successfully saved");

                        this.showFormInProgress(false);
                        this.redirectIfNecessary("status_overview");
                        
                    }.bind(this)
                )
                // Otherwise, show a failure message
                .fail(function (response) {
                    this.showFormInProgress(false);
                    this.showWarningMessage("Configuration could not be saved");
                }.bind(this));
                
                // Set the app as configured
                this.setConfigured();

            }

            return false;
        },
        
        /**
         * Sets the controls as enabled or disabled.
         */
        setControlsEnabled: function(enabled){

            if(enabled === undefined){
                enabled = true;
            }

            $('input,select', this.el).prop('disabled', !enabled);

        },

        /**
         * Make the form as in progress.
         */
        showFormInProgress: function(inProgress){
            $('.btn-primary').prop('disabled', inProgress);
            this.setControlsEnabled(!inProgress);

            if(inProgress){
                $('.btn-primary').text("Saving Configuration...");
            }
            else{
                $('.btn-primary').text("Save Configuration");
            }
        },

        /**
         * Fetch the app configuration data.
         */
        fetchAppConfiguration: function(){
            this.website_input_configuration = new WebsiteInputConfiguration();

            this.setControlsEnabled(false);

            return this.website_input_configuration.fetch({
                url: '/splunkd/services/admin/app_website_input/default',
                id: 'default',
                success: function (model, response, options) {
                    console.info("Successfully retrieved the default website_input configuration");
                    this.setProxyServer(model.entry.content.attributes.proxy_server);
                    this.setProxyServerPort(model.entry.content.attributes.proxy_port);
                    this.setProxyType(model.entry.content.attributes.proxy_type);

                    this.setProxyUser(model.entry.content.attributes.proxy_user);
                    this.setProxyPassword(model.entry.content.attributes.proxy_password);
                    this.setProxyPasswordConfirmation(model.entry.content.attributes.proxy_password);
                }.bind(this),
                error: function () {
                    console.warn("Unsuccessfully retrieved the default website_input configuration");
                }.bind(this)
            });
        },

        render: function () {

            if(this.userHasAdminAllObjects()){

                // Render the view
                this.$el.html(_.template(Template, {
                    'has_permission' : this.userHasAdminAllObjects()
                }));

                // Start the process of loading the app configurtion if necessary
                if(this.website_input_configuration === null){

                    this.setControlsEnabled(false);

                    $.when(
                        this.fetchAppConfiguration(),
                        this.getEncryptedCredential(this.secure_storage_stanza, true)
                    )
                    // If successful, then load the 
                    .then(
                        function(a, credential){

                            if(credential){
                                this.setProxyPassword(credential.entry.content.attributes.clear_password);
                                this.setProxyPasswordConfirmation(credential.entry.content.attributes.clear_password);
                            }

                            this.setControlsEnabled(true);
                        }.bind(this)
                    );

                }

            }
            else{
                this.$el.html("Sorry, you don't have permission to perform setup");
            }

        },

        /**
         * Below is a list of validators for the form fields.
         */
        isValidPort: function(value){
            var port = parseInt(value, 10); 

            if(value === ''){
                return true;
            }
            else if(isNaN(port)){
                return false;
            }
            else if(port < 1 || port > 65535){
                return false;
            }
            else{
                return true;
            }
        },

        matchesPassword: function(value){
            var originalPassword = this.getProxyPassword();

            if(originalPassword !== value){
                return false;
            }
            else{
                return true;
            }
        },

        isValidServer: function(value){

            var domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/gm;
            var ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;

            if(value === ''){
                return true;
            }
            else if(domainRegex.exec(value) || ipRegex.exec(value)){
                return true;
            }
            else{
                return false;
            }
        },

        /**
         * Setup the validators so that we can detect bad input
         */
        setupValidators: function(){
            // Note: the getters are defined by the SetupView which creates the setters and getters from formProperties
            this.addValidator('.proxy-address', this.getProxyServer.bind(this), this.isValidServer, "Must be a valid domain name or IP address");
            this.addValidator('.proxy-port', this.getProxyServerPort.bind(this), this.isValidPort, "Must be a valid port number");
            this.addValidator('.proxy-password-confirm', this.getProxyPasswordConfirmation.bind(this), this.matchesPassword.bind(this), "Must match the password");
        },
    });
});
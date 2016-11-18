require.config({
    paths: {
        "text": "../app/website_input/js/lib/text"
    }
});

define([
    "underscore",
    "backbone",
    "models/SplunkDBase",
    "collections/SplunkDsBase",
    "splunkjs/mvc",
    "util/splunkd_utils",
    "jquery",
    "splunkjs/mvc/simplesplunkview",
    'views/shared/controls/StepWizardControl',
    "splunkjs/mvc/simpleform/input/dropdown",
    "splunkjs/mvc/simpleform/input/text",
    'text!../app/website_input/js/templates/WebsiteInputCreateView.html',
    "bootstrap.dropdown",
    "css!../app/website_input/css/WebsiteInputCreateView.css"
], function(
    _,
    Backbone,
    SplunkDBaseModel,
    SplunkDsBaseCollection,
    mvc,
    splunkd_utils,
    $,
    SimpleSplunkView,
    StepWizardControl,
    DropdownInput,
    TextInput,
    Template
){
	
	var Indexes = SplunkDsBaseCollection.extend({
	    url: "data/indexes",
	    initialize: function() {
	      SplunkDsBaseCollection.prototype.initialize.apply(this, arguments);
	    }
	});
	
	var ScrapePageResults = Backbone.Collection.extend({
		initialize: function(models, options) {
		   this.provided_options = options;
	    },
	    url : function() {
	    	var url = Splunk.util.make_full_url("/custom/website_input/web_input_controller/scrape_page?") + jQuery.param(this.provided_options);
	    	console.log(url);
	        return url;
	     } 
	});
	
    // Define the custom view class
    var WebsiteInputCreateView = SimpleSplunkView.extend({
        className: "WebsiteInputCreateView",
        
        defaults: {
        	
        },
        
        events: {
        	"change #inputURL" : "clickUpdatePreview",
        	"click #do-preview" : "clickUpdatePreview",
        	"click .preview-url" : "clickUpdatePreview",
        	"click .clearSelector" : "clearSelector",
        	"change #inputSelector" : "changeInputSelector",
        	"keypress #inputSelector" : "keypressInputSelector"
        },
        
        initialize: function() {
        	this.options = _.extend({}, this.defaults, this.options);
        	
        	//this.some_option = this.options.some_option;
        	
        	// These are internal variables
        	this.capabilities = null;
        	this.inputs = null;
        	this.existing_input_names = [];
        	this.selector_gadget_added_interval = null;
        	this.previous_sg_value = null;
        	this.sg_loaded = false;
        	
        	// Get the list of existing inputs
        	this.getExistingInputs();
        	
        	// Get the indexes
        	this.indexes = new Indexes();
        	this.indexes.on('reset', this.gotIndexes.bind(this), this);
        	
        	this.indexes.fetch({
                success: function() {
                  console.info("Successfully retrieved the list of indexes");
                },
                error: function() {
                  console.error("Unable to fetch the indexes");
                }
            });
        	
        	// Start syncing the selector gadget back to the form
        	setInterval(this.syncSelectorGadget.bind(this), 100);
        	
        	// Start the interval to make sure that the selector gadget was loaded in the frame
        	setInterval(this.tryToLoadSelectorGadget.bind(this), 2000);
        },
        
        /**
         * Add the given item to the associative array if it is non-blank
         */
        addIfInputIsNonEmpty: function(d, name, inputid){
        	
        	if($(inputid, this.$el).val().length > 0){
        		d[name] = $(inputid, this.$el).val();
        	}
        	
        },
        
        /**
         * Add the given item to the associative array based on whether it is checked.
         */
        addCheckboxInput: function(d, name, inputid){
        	
        	if($(inputid, this.$el).is(":checked")){
        		d[name] = "1";
        	}
        	else{
        		d[name] = "0";
        	}
        	
        },
        
        /**
         * Render a list of URLs in the preview list
         */
        renderPreviewURLs: function(urls){
        	var html = "";
        	var option_template = _.template('<li><a href="#" data-url="<%- url %>" class="preview-url"><%- url %></a></li>');
        	
        	for(var c=0; c < urls.length; c++){
        		html += option_template({
        			"url" : urls[c]
        		})
        	}
        	
        	$('.preview-url-dropdown-selector').html(html);
        },
        
        /**
         * Update the list of preview URLs
         */
        updatePreviewURLs: function(){
        	
        	// Make the args
        	var args = {'selector' : "*"};
        	
        	this.addIfInputIsNonEmpty(args, 'page_limit', '#inputPageLimit');
        	this.addIfInputIsNonEmpty(args, 'depth_limit', '#inputDepthLimit');
        	this.addIfInputIsNonEmpty(args, 'url_filter', '#inputURLFilter');
        	this.addIfInputIsNonEmpty(args, 'uri', '#inputURL');
        	this.addIfInputIsNonEmpty(args, 'username', '#inputUsername');
        	this.addIfInputIsNonEmpty(args, 'password', '#inputPassword');
        	this.addIfInputIsNonEmpty(args, 'page_limit', '#inputPageLimit');
        	
        	// Place a limit on the page count of 10
        	if(parseInt(args['page_limit'], 10) > 10){
        		args['page_limit'] = '10';
        	}
        	
        	// Get the results
        	this.results = new ScrapePageResults([], args);
        	
        	$('.preview-urls-loading', this.$el).show();
        	
        	this.results.fetch({
                success: function() {
                	// Get a list of the URLs
                	var urls = [];
                	
                	for(var c=0; c < this.results.models.length; c++){
                		urls.push(this.results.models[c].get("url"));
                	}
                	
                	// Render the URLs if we got some
                	if(urls.length > 0){
                		this.renderPreviewURLs(urls);
                	}
                	
                	// If we didn't get any, then just use the input URL
                	else{
                		this.renderPreviewURLs([$("#inputURL", this.$el).val()]);
                	}
                	
                	// Hide the message noting that we are getting the list of URLs
                	$('.preview-urls-loading', this.$el).hide();
                	
                	console.info("Successfully retrieved the preview URLs");
                }.bind(this),
                error: function() {
                	$('.preview-urls-loading', this.$el).hide();
                  console.error("Unable to fetch the results");
                }.bind(this)
            });
        },
        
        /**
         * Get the given URL parameter.
         */
        getURLParameter: function(param){
        	var pageURL = window.location.search.substring(1);
            var sURLVariables = pageURL.split('&');
            for (var i = 0; i < sURLVariables.length; i++)
            {
                var parameterName = sURLVariables[i].split('=');
                if (parameterName[0] == param) 
                {
                    return decodeURIComponent(parameterName[1]);
                }
            }
            
            return null;
        },
        
        /**
         * Set the input to the given value if it isn't null or undefined.
         */
        setIfValueIsNonEmpty: function(input, value){
        	if(value !== null && value !== undefined){
        		$(input, this.$el).val(value);
        	}
        },
        
        /**
         * Set the checkbox to the given value.
         */
        setCheckboxInput: function(input, value){
        	if(value !== null && value !== undefined && (value === "1" ||  value.toLowerCase() === "true")){
        		$(input, this.$el).prop('checked', true);
        	}
        	else{
        		$(input, this.$el).prop('checked', false);
        	}
        },
        
        /**
         * Load the given input into the UI.
         */
        loadInput: function(input){
        	
        	// Generic options
        	//this.setIfValueIsNonEmpty(data, "source", '#inputSource');
        	if(input.content.name !== null){
        		 mvc.Components.getInstance("name").val(input.content.name);
        	}
        	
        	mvc.Components.getInstance("index").val(input.content.index);
        	mvc.Components.getInstance("host").val(input.content.host);
        	
        	if(input.content.sourcetype !== null){
        		mvc.Components.getInstance("sourcetype").val(input.content.sourcetype);
        	}
        	
        	// Input basics
        	this.setIfValueIsNonEmpty('#inputSelector', input.content.selector);
        	this.setIfValueIsNonEmpty('#inputURL', input.content.url);
        	this.setIfValueIsNonEmpty('#inputInterval', input.content.interval);
        	
        	if(input.content.title !== null){
        		mvc.Components.getInstance("title").val(input.content.title);
        	}
        	//this.setIfValueIsNonEmpty("timeout", '#inputTimeout', input.content.timeout);
        	//this.addIfInputIsNonEmpty("browser", '#inputBrowser', input.content.);
        	//this.addIfInputIsNonEmpty("user_agent", '#inputUserAgent', input.content.);
        	
        	// Crawling options
        	this.setIfValueIsNonEmpty('#inputPageLimit', input.content.page_limit);
        	this.setIfValueIsNonEmpty('#inputURLFilter', input.content.url_filter);
        	this.setIfValueIsNonEmpty('#inputDepthLimit', input.content.depth_limit);
        	
        	// Credentials
        	this.setIfValueIsNonEmpty('#inputUsername', input.content.username);
        	this.setIfValueIsNonEmpty('#inputPassword', input.content.password);
        	
        	// Output options
        	this.setIfValueIsNonEmpty('#inputNameAttributes', input.content.name_attributes);
        	this.setIfValueIsNonEmpty('#inputTextSeparator', input.content.text_separator);
        	
        	this.setCheckboxInput('#inputIncludeRaw', input.content.raw_content);
        	this.setCheckboxInput('#inputMV', input.content.output_as_mv);
        	this.setCheckboxInput('#inputUseTagAsField', input.content.use_element_name);
        	
        },
        
        /**
         * Get the given input.
         */
        fetchInput: function(input_name){
        	
        	var promise = $.Deferred();
        	
        	// Prepare the arguments
            var params = new Object();
            params.output_mode = 'json';
            
            var uri = splunkd_utils.fullpath("/services/data/inputs/web_input/" + encodeURIComponent(input_name));
            uri += '?' + Splunk.util.propToQueryString(params);
            
            // Fire off the request
            jQuery.ajax({
                url:     uri,
                type:    'GET',
                success: function(result) {
                	
                    if(result !== undefined && result.isOk === false){
                    	console.error("Input could not be obtained: " + result.message);
                    	promise.reject();
                    }
                    else if(result === undefined || result === null){
                    	console.error("Input could not be obtained: result object is null or undefined");
                    	promise.reject();
                    }
                    else{
                    	input = result.entry[0];
                    	
                    	promise.resolve(input);
                    }
                }.bind(this),
                // On error
    			error: function(jqXHR, textStatus, errorThrown){
    				promise.reject();
    			}.bind(this)
            });
            
            return promise;

        },
        
        /**
         * Handle changes to the input selector.
         */
        changeInputSelector: function(ev){
        	this.refreshSelector($("#inputSelector").val());
        },
        
        /**
         * Handle enter key to the input selector.
         */
        keypressInputSelector: function(ev){
        	
        	var code = ev.keyCode || ev.which;
        	
            if (code == 13){
            	this.refreshSelector($("#inputSelector").val());
            }
        },

        
        /**
         * Update the count of matches.
         */
        updateMatchCount: function(){
        	
        	var matches = "";
        	
        	if($("#inputSelector", this.$el).val().trim().length > 0){
        		matches = $($("#inputSelector", this.$el).val(), frames[0].window.document).length;
        	}
        	
        	// If we got nothing, then blank out the match count
        	if(matches === ""){
        		$('.match-count', this.$el).text(matches);
        	}
        	
        	// If we got one, then use the singular form
        	else if(matches === 1){
        		$('.match-count', this.$el).text("1 match in the current document");
        	}
        	
        	else if(matches > 1 || matches === 0){
        		$('.match-count', this.$el).text(matches + " matches in the current document");
        	}
        	
        },
        
        /**
         * Update the selector in the preview panel.
         */
        refreshSelector: function(selector){
        	
        	// Update the selector gadget if it has been loaded
        	if(frames[0].window.selector_gadget){
        		$(frames[0].window.selector_gadget.path_output_field).val(selector);
            	frames[0].window.selector_gadget.refreshFromPath();
            	this.previous_sg_value = selector;
        	}
        	
        	// Update the count of matches
        	this.updateMatchCount();
        },
        
        /**
         * Clear the given selector.
         */
        clearSelector: function(){
        	$("#_sg_div > input:nth-of-type(2)", frames[0].window.document).trigger("click");
        },
        
        /**
         * Get the indexes
         */
        gotIndexes: function(){
        	
        	// Update the list
        	if(mvc.Components.getInstance("index")){
        		mvc.Components.getInstance("index").settings.set("choices", this.getChoices(this.indexes, function(entry){
        			return !(entry.attributes.name[0] === "_");
        		}));
        	}
        	
        },
        
        /**
         * Get the list of a collection model as choices.
         */
        getChoices: function(collection, filter_fx){
        	
        	// Make a default for the filter function
        	if(typeof filter_fx === 'undefined'){
        		filter_fx = null;
        	}
        	
        	// If we don't have the model yet, then just return an empty list for now
        	if(!collection){
        		return [];
        	}
        	
        	var choices = [];
        	
        	for(var c = 0; c < collection.models.length; c++){
        		
        		// Stop if the filtering function says not to include this entry
        		if(filter_fx && !filter_fx(collection.models[c].entry) ){
        			continue;
        		}
        		
        		// Otherwise, add the entry
        		choices.push({
        			'label': collection.models[c].entry.attributes.name,
        			'value': collection.models[c].entry.attributes.name
        		});
        	}
        	
        	return choices;
        	
        },
        
        /**
         * Handle the case where the preview button was clicked.
         */
        clickUpdatePreview: function(ev){
        	var url = $(ev.target).data("url");
        	this.updatePreview(url);
        	return true;
        },
        
        /**
         * Try to load the selector gadget in the preview window if necessary.
         */
        tryToLoadSelectorGadget: function(){
    		if(this.sg_loaded){
    			return;
    		}
    		
    		// See if the selector gadget exists
    		if(typeof frames[0].window.selector_gadget !== 'undefined'){
    			//clearInterval(this.selector_gadget_added_interval);
    			return;
    		}
    		
    		// See if the document is ready and update it if it is
    		if( (frames[0].window.document.readyState === 'loaded'
    			|| frames[0].window.document.readyState === 'interactive'
    			|| frames[0].window.document.readyState === 'complete')
    			&& frames[0].window.document.body !== null
    			&& frames[0].window.document.body.innerHTML.length > 0
    			&& typeof frames[0].window.selector_gadget === 'undefined' ){
    			
    			console.log("Loading the selector gadget into the preview frame")
    			this.startSelectorGadget();
    			this.sg_loaded = true;
    		}
        },
        
        /**
         * Update the preview panel.
         */
        updatePreview: function(url){
        	this.sg_loaded = false;
        	
        	// Clear the existing page so that it is clear that we are reloading the page
        	$("#preview-panel", this.$el).attr("src", "");
        	
        	// Clear the preview
        	if(url === ""){
        		return;
        	}
        	
        	// Stop if a URL was not provided
        	if(!url){
        		return;
        	}
        	
        	// Prepare the arguments
            var params = new Object();
            params.url = url;
            
            if( $('#inputUsername', this.$el).val().length > 0 && $('#inputPassword', this.$el).val().length > 0 ){
            	params.username = $('#inputUsername', this.$el).val();
            	params.password = $('#inputPassword', this.$el).val();
            }
        	
            var uri = Splunk.util.make_url("/custom/website_input/web_input_controller/load_page")
            uri += '?' + Splunk.util.propToQueryString(params);
            
        	// Tell the iframe to load the URL
        	$("#preview-panel", this.$el).attr("src", uri);
        	
        	// Prevent links from working in the frame
        	$("iframe").load(function() {
        	    $("iframe").contents().find("a").each(function(index) {
        	        $(this).on("click", function(event) {
        	            event.preventDefault();
        	            event.stopPropagation();
        	        });
        	    });
        	});
        	
        	
        	return;
        },
        
        /**
         * This is a helper function to create a step.
         */
        createStep: function(step) {
        	
            // Make the model that will store the steps if it doesn't exist yet
        	if(this.steps === undefined){
        		this.steps = new Backbone.Collection();
        	}
            
        	// This is the instance of your new step
            var newStep = {
                label: _(step.label).t(),
                value: step.value,
                showNextButton: step.showNextButton !== undefined ? step.showNextButton : true,
                showPreviousButton: step.showPreviousButton !== undefined ? step.showPreviousButton : true,
                showDoneButton: step.showDoneButton !== undefined ? step.showDoneButton : false,
                doneLabel: step.doneLabel || 'Done',
                enabled: true,
                panelID: step.panelID,
                validate: function(selectedModel, isSteppingNext) {
                	
                    var promise = $.Deferred();
                    
                    // Get the response from the validation attempt (if a validateStep function is defined)
                    var validation_response = true;
                    
                    if(typeof this.validateStep !== undefined){
                    	validation_response = this.validateStep(selectedModel, isSteppingNext);
                    }
                    
                    // Based on the validation action, reject or resolve the promise accordingly to let the UI know if the user should be allowed to go to the next step
                    if(validation_response === true){
                    	promise.resolve();
                    }
                    else if(validation_response === false){
                    	promise.reject();
                    }
                    else{
                    	return validation_response; // This is a promise
                    }
                    
                    return promise;
                    
                }.bind(this),
            };

            return newStep;
        },
        
        /**
         * Make the steps.
         */
        initializeSteps: function(){
        	
        	var c = 0;
        	
            // Make the model that will store the steps
            this.steps = new Backbone.Collection();
        	
            // Create the steps
        	
        	// Step 1
            this.steps.add(this.createStep({
                label: 'Enter URL',
                value: 'url-edit',
                showNextButton: true,
                showPreviousButton: false,
                panelID: "#url-edit"
            }), {at: ++c});

            // Step 2
            this.steps.add(this.createStep({
                label: 'Enter Credentials',
                value: 'auth-edit',
                showNextButton: true,
                showPreviousButton: true,
                panelID: "#auth-edit"
            }), {at: ++c}); 
            
            // Step 3
            this.steps.add(this.createStep({
                label: 'Define CSS Selector',
                value: 'selector-edit',
                showNextButton: true,
                showPreviousButton: true,
                panelID: "#selector-edit"
            }), {at: ++c}); 
            
            // Step 4
            this.steps.add(this.createStep({
                label: 'Customize Output',
                value: 'output-edit',
                showNextButton: true,
                showPreviousButton: true,
                panelID: "#output-edit"
            }), {at: ++c});
            
            // Step 5
            this.steps.add(this.createStep({
                label: 'Define Input Settings',
                value: 'index-edit',
                showNextButton: true,
                showPreviousButton: true,
                panelID: "#index-edit"
            }), {at: ++c});
            
            // Step 6
            this.steps.add(this.createStep({
                label: 'Save Input',
                value: 'name-edit',
                showNextButton: true,
                showPreviousButton: true,
                panelID: "#name-edit"
            }), {at: ++c}); 
            
            // Step 7
            this.steps.add(this.createStep({
                label: 'Finish',
                value: 'final',
                showNextButton: false,
                showPreviousButton: false,
                showDoneButton: true,
                panelID: "#final"
            }), {at: ++c});  
        },
        
        /**
         * Clear the validation error.
         */
        clearValidationError: function(inputID){
        	addIfCheckboxInput
        	// Remove the error class
        	$(inputID).parent().parent().removeClass("error");
        },
        
        /**
         * Clear all validation errors.
         */
        clearValidationErrors: function(){
        	
        	// Remove the error class
        	$.each( $('input'), function( i, val ) {
        		
        		// Make sure this is a control group
        		if($(val).parent().parent().hasClass("control-group")){
            		// Remove the error class
            		$(val).parent().parent().removeClass("error");
            		
            		// Clear the error message
            		$('.help-inline', $(val).parent()).text("");
        		}

        	});
        },
        
        /**
         * Add the validation error.
         */
        addValidationError: function(inputID, message){
        	
        	// Add the error class to the 
        	$(inputID).parent().parent().addClass("error");
        	
        	// Determine if the input has the inline help box
        	if($(".help-inline", $(inputID).parent()).length === 0){
        		
        		// Add the inline help box
            	$('<span class="help-inline"></span>').insertAfter(inputID)
        	}
        	
        	// Set the message
        	$(".help-inline", $(inputID).parent()).text(message);
        	
        },
        
        /**
         * Returns true if the item is a valid interval.
         */
        isValidInterval: function(interval){
        	
        	var re = /^\s*([0-9]+([.][0-9]+)?)\s*([dhms])?\s*$/gi;
        	
        	if(re.exec(interval)){
        		return true;
        	}
        	else{
        		return false;
        	}
        },
        
        /**
         * Validate that changing steps is allowed.
         */
        validateStep: function(selectedModel, isSteppingNext){
        	
        	// Get the copy of the config
        	var data = this.makeConfig();
        	
        	var issues = 0;
        	
        	// Validate step 1
        	// Update the preview URLs if moving from the URL step
        	if(selectedModel.get("value") === 'url-edit' && isSteppingNext){
        		
        		// Clear existing validation errors
        		this.clearValidationErrors();
        		
        		// Validate the interval
        		if(!this.isValidInterval($("#inputInterval").val())){
        			this.addValidationError($("#inputInterval"), "Enter a valid interval");
        			issues += 1;
        		}
        		
        		// Validate the URL
        		if($("#inputURL").val().length === 0){
        			this.addValidationError($("#inputURL"), "Enter a valid URL");
        			issues += 1;
        		}
        		
        		// Validate the depth limit
        		if($("#inputDepthLimit").val().length !== 0 && $("#inputDepthLimit").val().match(/^[0-9]+$/gi) === null){
        			this.addValidationError($("#inputDepthLimit"), "Enter a valid integer");
        			issues += 1;
        		}
        		
        		// Validate the page limit
        		if($("#inputPageLimit").val().length !== 0 && $("#inputPageLimit").val().match(/^[0-9]+$/gi) === null){
        			this.addValidationError($("#inputPageLimit"), "Enter a valid integer");
        			issues += 1;
        		}
        		
        		// Validate the URL filter
        		// TODO
        	}
        	
        	// Validate step 2
        	if(selectedModel.get("value") === 'auth-edit' && isSteppingNext){
        		this.updatePreview($("#inputURL", this.$el).val());
    			this.renderPreviewURLs([$("#inputURL", this.$el).val()]);
    			this.updatePreviewURLs();
        	}
        	
        	// Validate step 3
        	if(selectedModel.get("value") === 'selector-edit' && isSteppingNext){
        		
        		// Validate the selector
        		if($("#inputSelector").val().length === 0){
        			$("#inputSelector").parent().parent().addClass("error");
        			issues += 1;
        		}
        	}
        	
        	// Validate step 4
        	
        	// Validate step 5
        	
        	// Validate step 6, complete save
        	if(selectedModel.get("value") === 'name-edit' && isSteppingNext){
        		var promise = $.Deferred();
            	
        		$.when(this.createInput(data)).then(function(){
        			promise.resolve();
        		})
        		.fail(function(msg){
        			alert("The input could not be saved: " + msg);
        			promise.reject();
        		});
        		
            	return promise;
        	}
        	
        	// Stop if issues are found
    		if(issues > 0){
    			return false;
    		}
    		else{
    			return true;
    		}
        },
        
        /**
         * Setup the step wizard.
         */
        setupStepWizard: function(initialStep){
        	
        	var wizard = new Backbone.Model({
                'currentStep': initialStep
              });

              wizard.on('change:currentStep', function(model, currentStep) {
                  this.steps.map((step) => {
                      step.stopListening();
                  });
                  
                  // Find the associated step model
                  var step = this.steps.find(function(step) {
                      return step.get('value') == currentStep;
                  });

                  // Show or hide the next button as necessary
                  if (step.get('showNextButton')) {
                      $('button.btn-next', this.$el).show();
                  } else {
                      $('button.btn-next', this.$el).hide();
                  }

                  // Show or hide the previous button as necessary
                  if (step.get('showPreviousButton')) {
                      $('button.btn-prev', this.$el).show();
                  } else {
                      $('button.btn-prev', this.$el).hide();
                  }

                  // Show or hide the done button as necessary
                  if (step.get('showDoneButton')) {
                      $('button.btn-finalize', this.$el).show();
                      $('button.btn-finalize', this.$el).text(step.get('doneLabel'));
                  } else {
                      $('button.btn-finalize', this.$el).hide();
                  }

                  // Hide all of the existing wizard views
                  $(".wizard-content", this.$el).hide();
                  
                  // Show the next panel
                  $(step.get('panelID'), this.$el).show();
                  
              }.bind(this));
              
              // This is just the initial hidden step
              this.steps.unshift({
                  label: "",
                  value: 'initial',
                  showNextButton: false,
                  showPreviousButton: false,
                  enabled: false,
              });
              
              // Create the step wizard control
              this.stepWizard = new StepWizardControl({
                  model: wizard,
                  modelAttribute: 'currentStep',
                  collection: this.steps,
              });
              
              // Render the step wizard
              $('#step-control-wizard', this.$el).append(this.stepWizard.render().el);
              
              // Hide all of the existing wizard views
              $(".wizard-content", this.$el).hide();
              
              // Go the initial step: find it first
              var initialStep = this.steps.find(function(step) {
                  return step.get('value') == initialStep;
              });
              
              // ... now show it
              $(initialStep.get('panelID'), this.$el).show();
              
              // Go to step one
              this.stepWizard.step(1);
        },
        
        /**
         * Parses a URL into chunks. See https://gist.github.com/jlong/2428561
         */
        parseURL: function(url){
        	var parser = document.createElement('a');
        	parser.href = url;

        	/*
        	parser.protocol; // => "http:"
        	parser.hostname; // => "example.com"
        	parser.port;     // => "3000"
        	parser.pathname; // => "/pathname/"
        	parser.search;   // => "?search=test"
        	parser.hash;     // => "#hash"
        	parser.host;     // => "example.com:3000"
        	*/
        	
        	return parser;
        },
        
        /**
         * Make a stanza name from a string.
         */
        generateStanzaFromString: function(str, existing_stanzas){
        
        	// Stop of the string is blank
        	if(str === undefined || str === null || str === ""){
        		return "";
        	}
        	
        	// Set a default value for the existing_stanzas argument
        	if( typeof existing_stanzas == 'undefined' || existing_stanzas === null){
        		existing_stanzas = [];
        	}
        	
        	// If we have no existing stanzas, then just make up a name and go with it
        	if(existing_stanzas.length === 0){
            	return str.replace(/[^a-z0-9_]/gi, "_").toLowerCase();
        	}
        	
        	var stanza_base = str.replace(/[^a-z0-9_]/gi, "_").toLowerCase();
        	var possible_stanza = stanza_base;
        	var stanza_suffix_offset = 0;
        	var collision_found = false;
        	
        	while(true){
        		
        		collision_found = false;
        		
        		// See if we have a collision
            	for(var c = 0; c < existing_stanzas.length; c++){
            		if(existing_stanzas[c] === possible_stanza){
            			collision_found = true;
            			break;
            		}
            	}
        		
            	// Stop if we don't have a collision
            	if(!collision_found){
            		return possible_stanza;
            	}
            	
            	// We have a collision, continue
            	else{
            		stanza_suffix_offset = stanza_suffix_offset + 1;
            		possible_stanza = stanza_base + "_" + stanza_suffix_offset;
            	}
        		    		
        	}
        },
        
        /**
         * Generate a suggested title from the URL.
         */
        generateTitleFromURL: function(url){
        	var parsed = this.parseURL(url);
        	return parsed.hostname;
        },
        
        /**
         * Generate a suggested stanza from the URL.
         */
        generateStanzaFromURL: function(url, existing_stanzas){
        	
        	var parsed = this.parseURL(url);
        	
        	return this.generateStanzaFromString(parsed.hostname);
        },
        
        /**
         * Get a list of the existing inputs.
         */
        getExistingInputs: function(){

        	var uri = splunkd_utils.fullpath("/services/data/inputs/web_input?output_mode=json");

	        // Fire off the request
        	jQuery.ajax({
        		url:     uri,
        		type:    'GET',
        		async:   false,
        		success: function(result) {
        			
        			if(result !== undefined){
        				this.inputs = result.entry;
        			}
        			
        			// Populate a list of the existing input names
        			this.existing_input_names = [];
        			
                	for(var c = 0; c < this.inputs.length; c++){
                		this.existing_input_names.push(this.inputs[c]["name"]);
                	}

        		}.bind(this)
        	});

        },
        
        /**
         * Add the given item to the associative array if it is non-blank
         */
        addIfNonEmpty: function(d, name, value){
        	
        	if(value){
        		d[name] = value;
        	}
        	
        },
        
        /**
         * Make an associative array representing the configuration that is being requested to persist.
         */
        makeConfig: function(){
        	
        	// Make the data that will be posted to the server
        	var data = {};
        	
        	// Generic options
        	//this.addIfInputIsNonEmpty(data, "source", '#inputSource');
        	if(mvc.Components.getInstance("name").val()){
        		data['name'] = mvc.Components.getInstance("name").val();
        	}
        	
        	if(mvc.Components.getInstance("index").val()){
        		data['index'] = mvc.Components.getInstance("index").val();
        	}
        	
        	if(mvc.Components.getInstance("host").val()){
        		data['host'] = mvc.Components.getInstance("host").val();
        	}
        	
        	if(mvc.Components.getInstance("sourcetype").val()){
        		data['sourcetype'] = mvc.Components.getInstance("sourcetype").val();
        	}
        	
        	// Input basics
        	this.addIfInputIsNonEmpty(data, "selector", '#inputSelector');
        	this.addIfInputIsNonEmpty(data, "url", '#inputURL');
        	this.addIfInputIsNonEmpty(data, "interval", '#inputInterval');
        	if(mvc.Components.getInstance("title").val()){
        		data['title'] = mvc.Components.getInstance("title").val();
        	}
        	//this.addIfInputIsNonEmpty(data, "timeout", '#inputTimeout');
        	//this.addIfInputIsNonEmpty(data, "browser", '#inputBrowser');
        	//this.addIfInputIsNonEmpty(data, "user_agent", '#inputUserAgent');
        	
        	// Crawling options
        	this.addIfInputIsNonEmpty(data, "page_limit", '#inputPageLimit');
        	this.addIfInputIsNonEmpty(data, "url_filter", '#inputURLFilter');
        	this.addIfInputIsNonEmpty(data, "depth_limit", '#inputDepthLimit');
        	
        	// Credentials
        	this.addIfInputIsNonEmpty(data, "username", '#inputUsername');
        	this.addIfInputIsNonEmpty(data, "password", '#inputPassword');
        	
        	// Output options
        	this.addIfInputIsNonEmpty(data, "name_attributes", '#inputNameAttributes');
        	this.addIfInputIsNonEmpty(data, "text_separator", '#inputTextSeparator');
        	
        	this.addCheckboxInput(data, "raw_content", '#inputIncludeRaw');
        	this.addCheckboxInput(data, "output_as_mv", '#inputMV');
        	this.addCheckboxInput(data, "use_element_name", '#inputUseTagAsField');
        	
        	
        	// Populate defaults for the arguments
        	if(!data.hasOwnProperty('name')){
        		data['name'] = this.generateStanzaFromURL(data['url'], this.existing_input_names);
        	}
        	
        	if(!data.hasOwnProperty('title')){
        		data['title'] = this.generateTitleFromURL(data['url']);
        	}
        	
        	return data;
        },
        
        /**
         * Create an input
         */
        createInput: function(config){
        	
        	// Get a promise ready
        	var promise = jQuery.Deferred();
        	
        	// Perform the call
        	$.ajax({
        			url: splunkd_utils.fullpath("/servicesNS/admin/website_input/data/inputs/web_input?output_mode=json"),
        			data: config,
        			type: 'POST',
        			
        			// On success
        			success: function(data) {
        				console.info('Input created');
        				
        				var app = data.entry[0].acl.app;
        				var owner = data.entry[0].acl.owner;
        				var name = data.entry[0].name;
        				
        			}.bind(this),
        		  
        			// On complete
        			complete: function(jqXHR, textStatus){
        				
        				// Handle cases where the input already existing or the user did not have permissions
        				if( jqXHR.status == 403){
        					console.info('Inadequate permissions');
        					this.showWarningMessage("You do not have permission to make inputs");
        				}
        				else if( jqXHR.status == 409){
        					console.info('Input already exists');
        				}
        				
        				promise.resolve();
        			  
        			}.bind(this),
        		  
        			// On error
        			error: function(jqXHR, textStatus, errorThrown){
        				
        				// Handle the case where the user lacks permission
        				if( jqXHR.status != 403){
        					promise.reject("You do not have permission to make inputs");
        				}
        				
        				// Handle the case where the name already exists
        				else if( jqXHR.status != 409 ){
        					promise.reject("An input with the given name already exists");
        				}
        				
        				// Handle general errors
        				else{
        					promise.reject("The input could not be created");
        				}
        				
    					
        			}.bind(this)
        	});
        	
        	return promise;
        },
        
        /**
         * Validate the inputs.
         */
        validate: function(){
        	
        	var issues = 0;
        	
        	return issues === 0;
        },
        
        /**
         * Returns true if the item is a valid URL.
         */
        isValidURL: function(url){
        	var regex = /^(https?:\/\/)?([\da-z\.-]+)([:][0-9]+)?([\/\w \.-]*)*\/?$/gi;
        	return regex.test(url);
        },
        
        /**
         * Returns true if the item is a valid interval.
         */
        isValidInterval: function(interval){
        	
        	var re = /^\s*([0-9]+([.][0-9]+)?)\s*([dhms])?\s*$/gi;
        	
        	if(re.exec(interval)){
        		return true;
        	}
        	else{
        		return false;
        	}
        },
        
        /**
         * Ensure that the tag is a valid URL.
         */
        validateURL: function(event) {
        	if(!this.isValidURL(event.item)){
        		
        		// Try adding the protocol to see if the user just left that part out.
        		if(this.isValidURL("http://" + event.item)){
        			$("#urls").tagsinput('add', "http://" + event.item);
        		}
        		
        		event.cancel = true;
        		
        	}
        },
        
        /**
         * Hide the given item while retaining the display value
         */
        hide: function(selector){
        	selector.css("display", "none");
        	selector.addClass("hide");
        },
        
        /**
         * Un-hide the given item.
         * 
         * Note: this removes all custom styles applied directly to the element.
         */
        unhide: function(selector){
        	selector.removeClass("hide");
        	selector.removeAttr("style");
        },
        
        /**
         * Hide the messages.
         */
        hideMessages: function(){
        	this.hideWarningMessage();
        	this.hideInfoMessage();
        },
        
        /**
         * Hide the warning message.
         */
        hideWarningMessage: function(){
        	this.hide($("#warning-message", this.$el));
        },
        
        /**
         * Hide the informational message
         */
        hideInfoMessage: function(){
        	this.hide($("#info-message", this.$el));
        },
        
        /**
         * Show a warning noting that something bad happened.
         */
        showWarningMessage: function(message){
        	$("#warning-message > .message", this.$el).text(message);
        	this.unhide($("#warning-message", this.$el));
        },
        
        /**
         * Show a warning noting that something bad happened.
         */
        showInfoMessage: function(message){
        	$("#info-message > .message", this.$el).text(message);
        	this.unhide($("#info-message", this.$el));
        },
        
        /**
         * Determine if the user has the given capability.
         */
        hasCapability: function(capability){

        	var uri = Splunk.util.make_url("/splunkd/__raw/services/authentication/current-context?output_mode=json");

        	if( this.capabilities === null ){

	            // Fire off the request
	            jQuery.ajax({
	            	url:     uri,
	                type:    'GET',
	                async:   false,
	                success: function(result) {

	                	if(result !== undefined){
	                		this.capabilities = result.entry[0].content.capabilities;
	                	}

	                }.bind(this)
	            });
        	}

            return $.inArray(capability, this.capabilities) >= 0;

        },
        
        /**
         * Synchronize the selector gadget back with the input in the editor if needed.
         */
        syncSelectorGadget: function(){
        	
        	// Stop if the selector gadget isn't initialized
        	if($("#_sg_path_field", frames[0].window.document).length === 0){
        		this.previous_sg_value = null;
        		return;
        	}
        	
    		// Get the current value
    		var value = $("#_sg_path_field", frames[0].window.document).val();
    		
    		// If we haven't set the value, then this means that the selector gadget has just been initialized. Sync the form element back to selector gadget.
    		if(this.previous_sg_value === null){
    			this.refreshSelector($("#inputSelector", this.$el).val());
    			return;
    		}
    		
    		// Do something since the value changed
    		if(value !== this.previous_sg_value){
    			
        		// See if the value is blank
        		if(value === "No valid path found."){
        			if($("#inputSelector", this.$el).val() !== ""){
        				$("#inputSelector", this.$el).val("");
        	        	this.updateMatchCount();
        			}
        		}
        		
        		// Otherwise, do something since the value changed
        		else if($("#inputSelector", this.$el).val() !== value){
        			$("#inputSelector", this.$el).val(value);
        			this.updateMatchCount();
        		}
        		
        		this.previous_sg_value = value;
    		}
        },
        
        /**
         * Start the selector gadget in the iframe.
         */
        startSelectorGadget: function(){
        	
        	var base_url = document.location.origin + Splunk.util.make_url("/static/app/website_input/js/lib/selectorgadget/");
        	
        	// This is a minified version of selectorgadget.js
        	frames[0].window.eval('function i18n_register(){};function importJS(a,b,c){var d=document.createElement("script");d.setAttribute("type","text/javascript"),d.setAttribute("src",a),c&&wait_for_script_load(b,c);var e=document.getElementsByTagName("head")[0];e?e.appendChild(d):document.body.appendChild(d)}function importCSS(a,b,c){var d=document.createElement("link");d.setAttribute("rel","stylesheet"),d.setAttribute("type","text/css"),d.setAttribute("media","screen"),d.setAttribute("href",a),c&&wait_for_script_load(b,c);var e=document.getElementsByTagName("head")[0];e?e.appendChild(d):document.body.appendChild(d)}function wait_for_script_load(look_for,callback){var interval=setInterval(function(){"undefined"!=eval("typeof "+look_for)&&(clearInterval(interval),callback())},50)}!function(){importCSS("baseurl/selectorgadget_hide.css"),importJS("baseurl/jquery.min.js","jQuery",function(){jQuery.noConflict(),importJS("baseurl/diff_match_patch.js","diff_match_patch",function(){importJS("baseurl/dom.js","DomPredictionHelper",function(){importJS("baseurl/interface.js")})})})}();'.replace(new RegExp("baseurl", 'g'), base_url));
        	
        	// Clear the selector
        	this.previous_sg_value = null;
        },
        
        /**
         * Get the selector from the gadget in the 
         */
        getSelectorFromGadget: function(){
        	return $("#preview-panel").contents().find("#_sg_path_field");
        },
        
        /**
         * Render the view.
         */
        render: function () {
        	
        	var has_permission = this.hasCapability('edit_modinput_web_input');
        	
        	this.$el.html(_.template(Template, {
        		'has_permission' : has_permission
        	}));
        	
        	// Make the indexes selection drop-down
            var indexes_dropdown = new DropdownInput({
                "id": "index",
                "selectFirstChoice": false,
                "showClearButton": true,
                "el": $('#inputIndexes', this.$el),
                "choices": this.getChoices(this.indexes)
            }, {tokens: true}).render();
            
        	// Make the sourcetype input
        	var sourcetype_input = new TextInput({
                "id": "sourcetype",
                "searchWhenChanged": false,
                "el": $('#inputSourcetype', this.$el)
            }, {tokens: true}).render();
        	
        	// Make the host input
        	var host_input = new TextInput({
                "id": "host",
                "searchWhenChanged": false,
                "el": $('#inputHost', this.$el)
            }, {tokens: true}).render();
        	
        	// Make the title input
        	var title_input = new TextInput({
                "id": "title",
                "searchWhenChanged": false,
                "el": $('#titleInput', this.$el)
            }, {tokens: true}).render();
    		
        	// Generate a name from the title if the name is blank
        	title_input.on("change", function(newValue) {
        		if(!mvc.Components.getInstance("name").val() && newValue !== ""){
        			mvc.Components.getInstance("name").val(this.generateStanzaFromString(newValue));
        		}
            }.bind(this));
        	
        	// Make the name input
        	var name_input = new TextInput({
                "id": "name",
                "searchWhenChanged": false,
                "el": $('#nameInput', this.$el)
            }, {tokens: true}).render();
    		
            // Initialize the steps model
            this.initializeSteps();
            
            // Create the step wizard and set the initial step as the "url-edit" step
            this.setupStepWizard('url-edit');
            
            // Render the input entry
        	// Fetch the default information
        	$.when(this.fetchInput("_new")).done(function(input){
        		console.log("Got the _new input");
        		this.default_input = input;
        		this.loadInput(this.default_input);
        	}.bind(this));
            
        }
    });
    
    return WebsiteInputCreateView;
});
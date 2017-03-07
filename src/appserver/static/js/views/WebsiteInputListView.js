
require.config({
    paths: {
        datatables: "../app/website_input/js/lib/DataTables/js/jquery.dataTables",
        bootstrapDataTables: "../app/website_input/js/lib/DataTables/js/dataTables.bootstrap",
        text: "../app/website_input/js/lib/text",
        console: '../app/website_input/js/lib/console'
    },
    shim: {
        'bootstrapDataTables': {
            deps: ['datatables']
        }
    }
});

define([
    "underscore",
    "backbone",
    "models/SplunkDBase",
    "collections/SplunkDsBase",
    "splunkjs/mvc",
    "jquery",
    "splunkjs/mvc/simplesplunkview",
    "text!../app/website_input/js/templates/WebsiteInputListView.html",
    "bootstrapDataTables",
    "util/splunkd_utils",
    "bootstrap.dropdown",
    "css!../app/website_input/css/WebsiteInputListView.css",
    "css!../app/website_input/css/SplunkDataTables.css"
], function(
    _,
    Backbone,
    SplunkDBaseModel,
    SplunkDsBaseCollection,
    mvc,
    $,
    SimpleSplunkView,
    Template,
    dataTable,
    splunkd_utils
){
	
	var Apps = SplunkDsBaseCollection.extend({
	    url: "apps/local?count=-1", //&search=disabled%3D0
	    initialize: function() {
	      SplunkDsBaseCollection.prototype.initialize.apply(this, arguments);
	    }
	});
	
	var WebsiteInputs = SplunkDsBaseCollection.extend({
	    url: "data/inputs/web_input/?count=-1",
	    initialize: function() {
	      SplunkDsBaseCollection.prototype.initialize.apply(this, arguments);
	    }
	});
	
    // Define the custom view class
    var WebsiteInputListView = SimpleSplunkView.extend({
        className: "WebsiteInputListView",
        
        defaults: {
        	change_dropdown_titles: true
        },
        
        /**
         * Initialize the class.
         */
        initialize: function() {
        	this.options = _.extend({}, this.defaults, this.options);
        	
        	// Save the options
        	this.change_dropdown_titles = this.options.change_dropdown_titles;
        	
            // Filtering options
            this.filter_app = null;
            this.filter_text = null;
			this.filter_scope = null;
            
            // This tracks the filter that was applied
            this.applied_filter = null;
            
            // This stores the list of apps
            this.apps = null;
            
            // The reference to the data-table
            this.data_table = null;
            
            // This indicates if data-table's state should be retained
            this.retain_state = false;
        	
        	// Get the inputs
        	this.getInputs();
        	
        	// Get the apps
        	this.apps = new Apps();
        	this.apps.on('reset', this.gotApps.bind(this), this);
        	
        	this.apps.fetch({
                success: function() {
                  console.info("Successfully retrieved the list of applications");
                },
                error: function() {
                  console.error("Unable to fetch the apps");
                }
            });
        	
        },
        
        events: {
        	// Filtering
        	"click .app-filter > .dropdown-menu > li > a" : "onClickAppFilter",
        	"change #free-text-filter" : "applyFilter",
        	"keyup #free-text-filter" : "goFilter",
        	"keypress #free-text-filter" : "goFilter",
			"click .scope-filter > .btn" : "onClickScopeFilter",
        	
        	// Options for disabling inputs
        	"click .disable-input" : "openDisableInputDialog",
        	"click #disable-this-input" : "disableInput",

        	// Options for deleting inputs
        	"click .delete-input" : "openDeleteInputDialog",
        	"click #delete-this-input" : "deleteInput",

            // Options for enabling inputs
            "click .enable-input" : "enableInput"
        },
        
        /**
         * Get the inputs
         */
        getInputs: function(){
        	this.inputs = new WebsiteInputs();
        	this.inputs.on('reset', this.gotInputs.bind(this), this);
        	
        	this.inputs.fetch({
                success: function() {
                  console.info("Successfully retrieved the inputs");
                },
                error: function() {
                  console.error("Unable to fetch the inputs");
                },
                complete: function(jqXHR, textStatus){
                	
                }.bind(this)
            });
        },
        
        /**
         * Apply the scope filter on click.
         */
        onClickScopeFilter: function(ev){
        	var filter = $(ev.target).text();
        	this.setScopeFilter(filter);
        },
        
        /**
         * Set the scope filter
         */
        setScopeFilter: function(filter){
        	
        	var filterText = "All";
        	
        	if(filter === "All" || filter === null){
        		this.filter_scope = null;
        	}
        	else if( filter.indexOf("Enabled") >= 0 ){
        		this.filter_scope = true;
        		filterText = "Disable";
        	}
        	else{
        		this.filter_scope = false;
        		filterText = "Enable";
        	}
        	
        	// Show the button as active on the selected entry and only on that entry
        	$('.scope-filter > .btn').each(function() {
        		if($(this).text() === filterText){
        			$(this).addClass('active');
        		}
        		else{
        			$(this).removeClass('active');
        		}
        	});
        	
        	this.applyFilter();
        	
        },

        /**
         * Set the name associated with the filter
         */
        setFilterText: function(filter_name, prefix, appendix){
        	
        	if (typeof appendix === "undefined") {
        		appendix = "All";
        	}
        	
    		if(this.change_dropdown_titles){
    			
    			if(appendix){
    				$("." + filter_name + " > .dropdown-toggle").html(prefix + ': ' + appendix + '<span class="caret"></span>');
    			}
    			else{
    				$("." + filter_name + " > .dropdown-toggle").html(prefix + '<span class="caret"></span>');
    			}
    			
    		}
        },
        
        /**
         * Perform the operation to perform a filter.
         */
        doFilter: function(filter_name, prefix, value, apply_filter){
        	
        	// Load a default for the apply_filter parameter
        	if( typeof apply_filter == 'undefined' ){
        		apply_filter = true;
        	}
        	
        	// Determine the value that should be checked
        	var valueToSet = value;
        	
        	if(value === null){
        		valueToSet = "All";
        	}
        	
        	// Set the text of the filter dropdown
        	this.setFilterText(filter_name, prefix, valueToSet);
        	
        	// Show the checked icon on the selected entry and only on that entry
        	$('.' + filter_name + ' > .dropdown-menu > li > a').each(function() {
        		if($(this).text() === valueToSet){
        			$("i", this).removeClass('hide');
        		}
        		else{
        			$("i", this).addClass('hide');
        		}
        	});
        	
        	// Apply the filter to the results
        	if(apply_filter){
        		this.applyFilter();
        	}
        	
        },
        
        /**
         * Apply the app filter on click.
         */
        onClickAppFilter: function(ev){
        	var filter = $(ev.target).text();
        	this.setAppFilter(filter);
        },
        
        /**
         * Set the app filter
         */
        setAppFilter: function(filter){
        	
        	if(filter === "All"){
        		this.filter_app = null;
        	}
        	else{
        		this.filter_app = filter;
        	}
        	
        	this.doFilter('app-filter', 'App', filter);
        	
        },
        
        /**
         * Enable the given input. 
         */
        enableInput: function(ev){
        	
        	// Get the input that is being requested to enable
        	var name = $(ev.target).data("name");
        	var namespace = $(ev.target).data("namespace");
        	var owner = $(ev.target).data("owner");
        	
        	// Perform the call
        	$.ajax({
        			url: splunkd_utils.fullpath(['/services/data/inputs/web_input', name, 'enable'].join('/')),
        			type: 'POST',
        			
        			// On success, populate the table
        			success: function() {
        				console.info('Input enabled');
        			}.bind(this),
        		  
        			// Handle cases where the file could not be found or the user did not have permissions
        			complete: function(jqXHR, textStatus){
        				if( jqXHR.status == 403){
        					console.info('Inadequate permissions to enable input');
        				}
        				else{
        					this.retain_state = true;
        					this.getInputs();
        				}
        				
        			}.bind(this),
        		  
        			// Handle errors
        			error: function(jqXHR, textStatus, errorThrown){
        				if( jqXHR.status != 403 ){
        					console.info('Input enablement failed');
        				}
        			}.bind(this)
        	});
        	
        	return false;
        },
        
        /**
         * Disable the given input. 
         */
        disableInput: function(ev){
        	
        	// Get the input that is being requested to disable
        	var input = $(ev.target).data("name");
        	var namespace = $(ev.target).data("namespace");
        	var owner = $(ev.target).data("owner");
        	
        	// Perform the call
        	$.ajax({
        			url: splunkd_utils.fullpath(['/servicesNS',  owner , namespace, '/data/inputs/web_input', input, 'disable'].join('/')),
        			type: 'POST',
        			
        			// On success
        			success: function() {
        				console.info('Input disabled');
        			}.bind(this),
        		  
        			// Handle cases where the file could not be found or the user did not have permissions
        			complete: function(jqXHR, textStatus){
        				if( jqXHR.status == 403){
        					console.info('Inadequate permissions to disable input');
        				}
        				else{
        					$("#disable-input-modal", this.$el).modal('hide');
        					this.retain_state = true;
        					this.getInputs();
        				}
        				
        			}.bind(this),
        		  
        			// Handle errors
        			error: function(jqXHR, textStatus, errorThrown){
        				if( jqXHR.status != 403 ){
        					console.info('Input disablement failed');
        				}
        			}.bind(this)
        	});
        	
        },
        
        /**
         * Open a dialog to disable the input.
         */
        openDisableInputDialog: function(ev){
        	
        	// Get the input that is being requested to disable
        	var name = $(ev.target).data("name");
        	var namespace = $(ev.target).data("namespace");
        	var owner = $(ev.target).data("owner");
        	
        	// Record the info about the input to disable
        	$("#disable-this-input", this.$el).data("name", name);
        	$("#disable-this-input", this.$el).data("namespace", namespace);
        	$("#disable-this-input", this.$el).data("owner", owner);
        	
        	// Show the info about the input to disable
        	$(".disable-input-name", this.$el).text(name);
        	$(".disable-input-namespace", this.$el).text(namespace);
        	$(".disable-input-owner", this.$el).text(owner);
        	
        	// Show the modal
        	$("#disable-input-modal", this.$el).modal();
        	
        	return false;
        	
        },

        /**
         * Open a dialog to delete the input.
         */
        openDeleteInputDialog: function(ev){
        	
        	// Get the input that is being requested to delete
        	var name = $(ev.target).data("name");
        	var namespace = $(ev.target).data("namespace");
        	var owner = $(ev.target).data("owner");
        	
        	// Record the info about the input to delete
        	$("#delete-this-input", this.$el).data("name", name);
        	$("#delete-this-input", this.$el).data("namespace", namespace);
        	$("#delete-this-input", this.$el).data("owner", owner);
        	
        	// Show the info about the input to delete
        	$(".delete-input-name", this.$el).text(name);
        	$(".delete-input-namespace", this.$el).text(namespace);
        	$(".delete-input-owner", this.$el).text(owner);
        	
        	// Show the modal
        	$("#delete-input-modal", this.$el).modal();
        	
        	return false;
        	
        },
        
        /**
         * Delete the given input. 
         */
        deleteInput: function(ev){
        	
        	// Get the input that is being requested to delete
        	var input = $(ev.target).data("name");
        	var namespace = $(ev.target).data("namespace");
        	var owner = $(ev.target).data("owner");
        	
        	// Perform the call
        	$.ajax({
        			url: splunkd_utils.fullpath(['/servicesNS',  owner , namespace, '/data/inputs/web_input', input].join('/')),
        			type: 'DELETE',
        			
        			// On success
        			success: function() {
        				console.info('Input deleted');
        			}.bind(this),
        		  
        			// Handle cases where the file could not be found or the user did not have permissions
        			complete: function(jqXHR, textStatus){
        				if( jqXHR.status == 403){
        					console.info('Inadequate permissions to delete input');
        				}
        				else{
        					$("#delete-input-modal", this.$el).modal('hide');
        					this.retain_state = true;
        					this.getInputs();
        				}
        				
        			}.bind(this),
        		  
        			// Handle errors
        			error: function(jqXHR, textStatus, errorThrown){
        				if( jqXHR.status != 403 ){
        					console.info('Input deletion failed');
        				}
        			}.bind(this)
        	});
        	
        },

        /**
         * Apply a filter to the table
         */
        goFilter: function(ev){
        	
        	var code = ev.keyCode || ev.which;
        	
            if (code == 13){
            	ev.preventDefault();
            }
        	
        	this.applyFilter();
        },
        
        /**
         * Get the description for the app name
         */
        getAppDescriptionFromName: function(name){
        	
    		for(var c = 0; c < this.apps.models.length; c++){
    			
    			if(this.apps.models[c].entry.attributes.name === name){
    				return this.apps.models[c].entry.associated.content.attributes.label;
    			}
    			
    		}
    		
    		return name;
        	
        },
        
        /**
         * Apply a filter to the table
         */
        applyFilter: function(){
        	
        	// Determine if we even need to apply this filter
        	var applied_filter_signature = ":" + this.filter_app + ":" + $('#free-text-filter').val() + ":" + this.filter_scope;
        	
        	if(applied_filter_signature === this.applied_filter){
        		return;
        	}
        	
        	// Persist the signature for this filter
        	this.applied_filter = applied_filter_signature;
        	
        	// Get the app filter
        	if( this.filter_app !== null ){
        		this.data_table.columns(2).search( "^" + this.filter_app + "$", true );
        	}
        	else{
        		this.data_table.columns(2).search( "" );
        	}

			// Get the scope filter
			if( this.filter_scope === true ){
        		this.data_table.columns(3).search( ".*Disable.*", true );
        	}
        	else if( this.filter_scope === false ){
        		this.data_table.columns(3).search( ".*Enable.*", true );
        	}
        	else{
        		this.data_table.columns(3).search( "" );
        	}
        	
        	// Apply the text filter
        	this.filter_text = $('#free-text-filter').val();
        	this.data_table.columns([0.1]).search( $('#free-text-filter').val() ).draw();
        },
        
        /**
         * Got the apps
         */
        gotApps: function(){
        	this.renderList();
        },
        
        /**
         * Got the inputs
         */
        gotInputs: function(){
        	this.renderList();
        },
        
        /**
         * Determine if the string end with a sub-string.
         */
        endsWith: function(str, suffix) {
            return str.indexOf(suffix, str.length - suffix.length) !== -1;
        },
        
        /**
         * Get a count of the inputs that exist.
         */
        getInputsCount: function(){
        	var inputs = this.getInputsJSON();
        	
        	if(inputs){
        		return inputs.length;
        	}
        	else{
        		return 0;
        	}
        },
        
        /**
         * Get the inputs list in JSON format
         */
        getInputsJSON: function(){
        	
        	var inputs_json = [];
        	var new_entry = null;
        	
        	// Add the inputs
        	for(var c = 0; c < this.inputs.models.length; c++){
        		
        		new_entry = {
        				'name': this.inputs.models[c].entry.attributes.name,
        				'title': this.inputs.models[c].entry.content.attributes.title,
        				'namespace': this.inputs.models[c].entry.acl.attributes.app,
        				'owner': this.inputs.models[c].entry.acl.attributes.owner,
        				'disabled': this.inputs.models[c].entry.associated.content.attributes.disabled
        		};
        		
        		inputs_json.push(new_entry);
        	}
        	
        	return inputs_json;
        },
        
        /**
         * Get the apps list in JSON format
         */
        getAppsJSON: function(only_include_those_with_inputs){
        	
        	// Set a default for the parameter
        	if (typeof only_include_those_with_inputs === "undefined") {
        		only_include_those_with_inputs = true;
        	}
        	
        	// If we don't have the apps yet, then just return an empty list for now
        	if(!this.apps){
        		return [];
        	}
        	
        	var apps_json = [];
        	var new_entry = null;
        	
        	for(var c = 0; c < this.apps.models.length; c++){
        		
        		new_entry = {
        				'name': this.apps.models[c].entry.attributes.name,
        				'label': this.apps.models[c].entry.associated.content.attributes.label
        		};
        		
        		// Filter out the items that are not for an app that exposes a website input
        		if(only_include_those_with_inputs){
        			
	        		// Find out of the item is for an app that publishes an input
	        		for(var d = 0; d < this.inputs.models.length; d++){
	        			
	        			if(this.inputs.models[d].entry.acl.attributes.app === this.apps.models[c].entry.attributes.name){
	        				apps_json.push(new_entry);
	        				break;
	        			}
	        		}
        		}
        		
        		// Otherwise, just include all of them
        		else{
        			apps_json.push(new_entry);
        		}
        		
        	}
        	
        	// Deduplicate the list
        	var apps_json = _.uniq(apps_json, function(item, key, a) { 
        	    return item.name;
        	});
        	
        	return apps_json;
        },
        
        /**
         * Render the list.
         */
        renderList: function(retainState){
        	
        	// Load a default for the retainState parameter
        	if( typeof retainState == 'undefined' ){
        		retainState = this.retain_state;
        	}
        	
        	// Get the template
            var input_list_template = $('#list-template', this.$el).text();
            
        	$('#content', this.$el).html(_.template(input_list_template, {
        		'inputs' : this.getInputsJSON(),
        		'apps' : this.getAppsJSON(),
        		'filter_app': this.filter_app,
        		'filter_text': this.filter_text,
        		'inputs_count' : this.getInputsCount(),
        		'getAppDescriptionFromName' : this.getAppDescriptionFromName.bind(this)
        	}));
        	
            // Make the table filterable, sortable and paginated with data-tables
            this.data_table = $('#table', this.$el).DataTable( {
                "iDisplayLength": 25,
                "bLengthChange": false,
                "searching": true,
                "aLengthMenu": [[ 25, 50, 100, -1], [25, 50, 100, "All"]],
                "bStateSave": true,
                "fnStateLoadParams": function (oSettings, oData) {
                	return retainState;
                },
                "aaSorting": [[ 1, "asc" ]],
                "aoColumns": [
                              null,                   // Name
                              null,                   // Title
                              { "searchable": false },// App
                              null // Actions
                            ]
            } );
            
            // Update the app filter
            this.setAppFilter(this.filter_app);
        },
        
        /**
         * Render the page.
         */
        render: function () {
        	this.$el.html(Template);
        }
    });
    
    return WebsiteInputListView;
});
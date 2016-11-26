define([
    "underscore",
    "backbone",
    "splunkjs/mvc",
    "jquery",
    "splunkjs/mvc/simplesplunkview",
    'text!../app/website_input/js/templates/PreviewWebsiteInputResultsView.html',
    "css!../app/website_input/css/PreviewWebsiteInputResultsView.css"
], function(
    _,
    Backbone,
    mvc,
    $,
    SimpleSplunkView,
    Template
){
    return SimpleSplunkView.extend({
        className: "PreviewWebsiteInputResultsView",
        
        defaults: {
        	
        },
        
        /**
         * Constructor
         */
        initialize: function() {
        	this.options = _.extend({}, this.defaults, this.options);
        	this.input_config = this.options.input_config;
        },
        
        /**
         * Show the dialog.
         */
        showDialog: function(){
        	$('#preview-results-modal', this.$el).modal();
        },
        
    	/**
    	 * Round the given number to one decimal point
    	 */
    	round: function(n){
    		return Math.round(n*10)/10.0;
    	},
    	
    	/**
    	 * Get a human readable version of the response time.
    	 */
    	getHumanReadableResponseTime: function(rtime) {
    		
    		if( rtime > (60 * 1000) ){
    	    	return String(this.round(rtime/60.0 * 1000)) + " minutes";
    	    }
    	    else if( rtime > (1000) ){
    	    	return String(this.round(rtime/1000.0)) + " seconds";
    	    }
    	    else{
    	    	return String(this.round(rtime)) + " ms";
    	    }
    	},
    	
    	/**
    	 * Get a human readable version of the bytes downloaded.
    	 */
    	getHumanReadableBytes: function(bytes) {
    	    if( bytes > (1024 * 1024) ){
    	    	return String(this.round(bytes/(1024* 1024.0))) + " MB";
    	    }
    	    else if( bytes > 1024 ){
    	    	return String(this.round(bytes/1024.0)) + " KB";
    	    }
    	    else{
    	    	return String(bytes) + " bytes";
    	    }
    	},
        
        /**
         * Update the preview.
         */
        updatePreview: function(input_config){
        	
        	// Indicate that the preview is happening
        	$('.preview-loading', this.$el).show();
        	
        	// Prepare the arguments
            var params = new Object();
            
            var uri = Splunk.util.make_url("/custom/website_input/web_input_controller/scrape_page");
            uri += '?' + Splunk.util.propToQueryString(params);
            
        	// Place a limit on the page count of 10
        	if(parseInt(params['page_limit'], 10) > 10){
        		params['page_limit'] = '10';
        	}
        	
        	// Get the results
        	$.ajax({
    			url: Splunk.util.make_full_url("/custom/website_input/web_input_controller/scrape_page"),
    			data: input_config,
    			type: 'POST',
                success: function(results) {
                	
                	// Store the results
                	this.results = results;
                	
                	// Render the URLs if we got some
                	if(results.length === 0){
                		// TODO show message
                	}
                	
                	// Otherwise, render the results
                	else{
                		this.render();
                		this.showDialog();
                	}
                	
                	// Hide the message noting that we are getting the results
                	$('.preview-loading', this.$el).hide();
                	
                	console.info("Successfully retrieved the results preview");
                }.bind(this),
                error: function() {
                	$('.preview-loading', this.$el).hide();
                	console.error("Unable to fetch the results");
                }.bind(this)
        	});
        	
        	return;
        },
        
        /**
         * Render the given view.
         */
        render: function () {
        	
        	this.$el.html(_.template(Template, {
        		'results' : this.results,
        		'round' : this.round.bind(this),
        		'getHumanReadableResponseTime' : this.getHumanReadableResponseTime.bind(this),
        		'getHumanReadableBytes' : this.getHumanReadableBytes.bind(this)
        	}));
        	
        }
    });
});
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
        
        events: {
        	"click .page" : "clickChangePage",
        	"click .previous-page" : "clickPreviousPage",
        	"click .next-page" : "clickNextPage"
        },
        
        /**
         * Constructor
         */
        initialize: function() {
        	this.options = _.extend({}, this.defaults, this.options);
        	this.input_config = this.options.input_config;
        	
        	this.results = null;
        	this.dialog_rendered = false;
        	this.page = 0;
        	this.error_message = null;
        },
        
        /**
         * Change the page to the selected page.
         */
        clickChangePage: function(ev){
        	var page = $(ev.target).data("page");
        	this.page = parseInt(page, 10);
        	
        	this.render();
        },
        
        /**
         * Change the page to the previous page.
         */
        clickPreviousPage: function(ev){
        	this.page = this.page - 1;
        	
        	if(this.page < 0){
        		this.page = 0;
        	}
        	
        	this.render();
        },
        
        /**
         * Change the page to the previous page.
         */
        clickNextPage: function(ev){
        	this.page = this.page + 1;
        	
        	if(this.page >= this.results.length){
        		this.page = this.results.length - 1;
        	}
        	
        	this.render();
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
        	
        	// Clear any prior results
        	this.results = null;
        	this.page = 0;
        	this.error_message = null;
        	
        	// Show the dialog to make it clear that the preview is happening
        	this.render();
    		this.showDialog();
        	
        	// Place a limit on the page count of 10
        	if(parseInt(input_config['page_limit'], 10) > 10){
        		input_config['page_limit'] = '10';
        	}
        	
        	// Specify a match prefix so that we can identify result fields easily
        	input_config['match_prefix'] = 'result_field_';
        	
        	// Get the results
        	$.ajax({
    			url: Splunk.util.make_full_url("/custom/website_input/web_input_controller/scrape_page"),
    			data: input_config,
    			type: 'POST',
                success: function(results) {
                	
                	// See if this is a message noting that something didn't work
                	if(results.hasOwnProperty('success') && !results.success){
                		this.error_message = results.messages[0].message;
                	}
                	else{
                		// Store the results
                    	this.results = results;
                    	this.error_message = null;
                	}
                	
                	
                	// Render the URLs if we got some
                	this.render();
                	
                	console.info("Successfully retrieved the results preview");
                }.bind(this),
                error: function() {
                	console.error("Unable to fetch the results");
                	this.error_message = "Unable to fetch the results";
                	this.render();
                }.bind(this)
        	});
        	
        	return;
        },
        
        /**
         * Render the given view.
         */
        render: function () {
        	
        	// Make the parameters for the HTML
        	var args = {
            		'results' : this.results,
            		'round' : this.round.bind(this),
            		'getHumanReadableResponseTime' : this.getHumanReadableResponseTime.bind(this),
            		'getHumanReadableBytes' : this.getHumanReadableBytes.bind(this),
            		'render_dialog_too' : !this.dialog_rendered,
            		'page' : this.page,
            		'error_message' : this.error_message
            };
        	
        	// Render the HTML
        	if(this.dialog_rendered){
        		$('#preview-results-modal > .modal-body-scrolling', this.$el).html(_.template(Template, args));
        	}
        	else{
        		this.$el.html(_.template(Template, args));
        		this.dialog_rendered = true;
        	}
        	
        }
    });
});
require.config({
    paths: {
    	website_input_create_view: '../app/website_input/js/views/WebsiteInputCreateView'
    }
});

require(['jquery','underscore','splunkjs/mvc', 'website_input_create_view', 'splunkjs/mvc/simplexml/ready!'],
	function($, _, mvc, WebsiteInputCreateView){

		var website_input_create_view = new WebsiteInputCreateView({'el' : '#input_view'});
		website_input_create_view.render();
	    
	}
);

require.config({
    paths: {
        web_input_list: "../app/website_input/js/views/WebsiteInputListView"
    }
});

require([
         "jquery",
         "underscore",
         "backbone",
         "web_input_list",
         "splunkjs/mvc/simplexml/ready!"
     ], function(
         $,
         _,
         Backbone,
         WebsiteInputListView
     )
     {
         
         var websiteInputListView = new WebsiteInputListView({
        	 el: $('#web_input_list')
         });
         
         websiteInputListView.render();
     }
);
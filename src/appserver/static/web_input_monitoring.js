require.config({
    paths: {
    	website_input_cell_renderer: '../app/website_input/WebsiteInputCellRenderer'
    }
});

require(['jquery','underscore','splunkjs/mvc', 'website_input_cell_renderer', 'splunkjs/mvc/searchmanager', 'splunkjs/mvc/simplexml/ready!'],
	function($, _, mvc, WebsiteInputCellRenderer, InfoMessageView, SearchManager){
	
		// Setup the cell renderer
	    var statusTable = mvc.Components.get('element1');
	
	    statusTable.getVisualization(function(tableView){
	        tableView.table.addCellRenderer(new WebsiteInputCellRenderer());
	        tableView.table.render();
	    });
	    
	}
);
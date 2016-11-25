require.config({
    paths: {
    	website_input_cell_renderer: '../app/website_input/WebsiteInputCellRenderer',
    	website_input_row_renderer: '../app/website_input/WebsiteInputRowRenderer',
    }
});

require(['jquery','underscore','splunkjs/mvc', 'website_input_cell_renderer', 'website_input_row_renderer', 'splunkjs/mvc/tableview', 'splunkjs/mvc/simplexml/ready!'],
	function($, _, mvc, WebsiteInputCellRenderer, WebsiteInputRowRenderer, TableView){
		
		// Setup the cell renderer
	    var statusTable = mvc.Components.get('element1');
	    
	    statusTable.getVisualization(function(tableView){
	    	tableView.addRowExpansionRenderer(new WebsiteInputRowRenderer());
	        tableView.addCellRenderer(new WebsiteInputCellRenderer());
	        tableView.render();
	    });
	    
	    
	}
);
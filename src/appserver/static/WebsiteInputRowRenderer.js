define(['jquery', 'underscore', 'splunkjs/mvc', 'splunkjs/mvc/tableview'], function($, _, mvc, TableView) {
    // See http://dev.splunk.com/view/webframework-developapps/SP-CAAAEUY
    var WebsiteInputRowRenderer = TableView.BaseRowExpansionRenderer.extend({
    	
        canRender: function(rowData) {
        	return true;
        },

        getResponseCodeDescription: function(response_code){
        	var intValue = parseInt(response_code, 10);
        	
        	var knownRequestCodes = {
        		100: "(request should continue)",
        		101: "(client should switch protocols)",
        		200: "(request has succeeded)",
        		201: "(new resource created)",
        		202: "(request should continue)",
        		203: "(non-authoritative information)",
        		204: "(no content)",
        		205: "(rest content)",
        		206: "(partial content)",
        		
        		300: "(multiple choices)",
        		301: "(moved permanently)",
        		302: "(found)",
        		303: "(see other)",
        		304: "(not modified)",
        		305: "(use proxy)",
        		307: "(temporary redirect)",
        		
        		400: "(bad request)",
        		401: "(unauthorized)",
        		402: "(payment required)",
        		403: "(forbidden)",
        		404: "(not found)",
        		405: "(method not allowed)",
        		406: "(not acceptable)",
        		407: "(proxy authentication required)",
        		408: "(request timeout)",
        		409: "(conflict)",
        		410: "(gone)",
        		411: "(length required)",
        		412: "(precondition failed)",
        		413: "(request entity too large)",
        		414: "(request URI too long)",
        		415: "(unsupported media type)",
        		416: "(requested range not satisfiable)",
        		417: "(expectation failed)",
        		
        		500: "(internal server error)",
        		501: "(functionality not implemented)",
        		502: "(bad gateway)",
        		503: "(service not available)",
        		504: "(gateway timeout)",
        		505: "(HTTP version not supported)",
        	};
        	
        	if(isNaN(intValue)){
        		return "";
        	}
        	
        	// See if the request is recognized
        	if(knownRequestCodes.hasOwnProperty(intValue)){
        		return knownRequestCodes[intValue];
        	}
        	// Otherwise, switch to the using the generic categories
        	if(intValue >= 600){
        		return " (unknown definition)";
        	}
        	else if(intValue >= 500){
        		return " (server error)";
        	}
        	else if(intValue >= 400){
        		return " (client error)";
        	}
        	else if(intValue >= 300){
        		return " (redirection)";
        	}
        	else if(intValue >= 200){
        		return " (request ok)";
        	}
        	else if(intValue >= 100){
        		return " (informational status)";
        	}
        },
        
        openURL: function(ev){
        	window.open($(this).attr("href"), '_blank');
        },
        
        parseURL: function(href) {
        	
        	if(!href){
        		return null;
        	}
        	
		    var l = document.createElement("a");
		    l.href = href;
		    return l;
        },
        
        getHostname: function(href){
        	var url_parsed = this.parseURL(href);
        	
        	if(url_parsed){
        		return url_parsed.hostname;
        	}
        	else{
        		return null;
        	}
        },
        
        render: function($container, rowData) {
        	
        	var html = '<ul class="list-dotted">' +
        		'<dt>Name:</dt><dd>web_input://<%- source %></dd>' + // <a target="_blank" onclick="document.location=\'edit_web_input?name=<%- source %>\'" href="edit_web_input?name=<%- source %>">[Edit input]</a>
        		'<dt>Unique URLs:</dt><dd><%- unique_urls_count %></dd>' + 
        		'<dt>Response Code:</dt><dd><%- response_code %></dd>' + 
        		'<% if(url){ %><dt>URL:</dt><dd><img height="16" width="16" src="http://www.google.com/s2/favicons?domain=<%- domain %>" /> <a href="<%- url %>"><%- url %></a></dd><% } %>' + 
        		'</ul>';
        	
        	// Convert the cell data into an associative array
        	var cellData = {};
        	
        	for(var c = 0; c < rowData.cells.length; c++){
        		cellData[rowData.cells[c].field] = rowData.cells[c].value;
        	}
        	
            // Display some of the rowData in the expanded row
            $container.append(_.template(html, {
        		'source' : cellData.source,
        		'unique_urls_count' : cellData.unique_urls,
        		'response_code' : cellData.response_code + " " + this.getResponseCodeDescription(cellData.response_code),
        		'url' : cellData.url,
        		'domain' : this.getHostname(cellData.url)
        	}));
            
            // Wire up a click handler so that the URL can be opened. A normal a tag won't work due to the way Splunk wires up the drill-down handlers on the rows.
            $('a', $container).click(this.openURL);
        }
	});
    
    return WebsiteInputRowRenderer;
});
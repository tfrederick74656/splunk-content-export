/*************************
Splunk Rule Downloader
Written by Tyler Frederick (tyler.frederick@securityriskadvisors.com)
Version 2.0, 05/31/2017

Changelog:
2.0 - Final Release, cleanup comments and code
1.7 - Add support for Saved Searches
1.6 - Add support for Views and XML file export
1.5 - Add support for Entity Investigator Search (Swimlane Searches)
1.4 - Add support for Key Indicators
1.3 - Initial Release w/ Support for Correlation Searches
*************************/

// TSV Data
var data;
var filename;
const TSV_EXT = ".tsv"
const URL = String(window.location.href);

// TSV Creator
function append(key, value){data = data + key + "\t" + String(value) + "\r\n";}

// For keys with multiple values
function startKey(key){data = data + key;}
function valueOnly(value){data = data + "\t" + String(value)}
function endKey(){data = data + "\r\n"}

function acquireCorrelationSearch(){
	filename = document.getElementsByName("name")[0].value + TSV_EXT
	append("URL", URL);

	// Correlation Search
	append("Search Name", document.getElementsByName("name")[0].value);
	append("Application Context", document.getElementsByName("namespace")[0].value);
	append("Description", document.getElementsByName("description")[1].value);
	append("Search", document.getElementsByName("search")[0].value);

	// Time Range
	append("Start time", document.getElementsByName("start_time")[0].value);
	append("End time", document.getElementsByName("end_time")[0].value);
	append("Cron Schedule", document.getElementsByName("cron_schedule")[0].value);
	var e = document.getElementsByName("realtime_schedule_isenabled")[0];
	append("Scheduling", e.options[e.selectedIndex].innerHTML);

	// Throttling
	append("Window Duration", document.getElementsByName("duration")[0].value);
	startKey("Fields to group by");
	var arr = document.getElementsByClassName("tm-tag");
	for (var i = 0, len = arr.length; i < len; i++) {
	  valueOnly(arr[i].childNodes[0].innerHTML);
	};
	endKey();

	// Notable Event
	append("Create notable event", document.getElementsByName("notable_isenabled")[0].checked);
	append("Title", document.getElementsByName("rule_title")[0].value);
	append("Description", document.getElementsByName("rule_description")[0].value);
	var e = document.getElementsByName("domain")[0];
	if(e.selectedIndex != -1) {
		append("Security Domain", e.options[e.selectedIndex].value);
	};
	var e = document.getElementsByName("severity")[0];
	append("Severity", e.options[e.selectedIndex].value);
	var e = document.getElementsByName("default_owner")[0];
	append("Default Owner", e.options[e.selectedIndex].innerHTML);
	var e = document.getElementsByName("default_status")[0];
	append("Default Status", e.options[e.selectedIndex].innerHTML);
	append("Drill-down name", document.getElementsByName("drilldown_name")[0].value);
	append("Drill-down search", document.getElementsByName("drilldown_search")[0].value);
	append("Drill-down earliest offset", document.getElementsByName("drilldown_earliest_offset")[0].value);
	append("Drill-down latest offset", document.getElementsByName("drilldown_latest_offset")[0].value);

	// Risk Scoring
	append("Create risk modifier", document.getElementsByName("risk_isenabled")[0].checked);
	append("Score", document.getElementsByName("risk_score")[0].value);
	append("Risk object field", document.getElementsByName("risk_object")[0].value);
	append("Risk object type", document.getElementsByClassName("select2-chosen")[0].innerHTML);

	// Actions
	append("Include in RSS feed", document.getElementsByName("rss_isenabled")[0].checked);
	append("Send email", document.getElementsByName("email_isenabled")[0].checked);
	append("Email subject", document.getElementsByName("email_subject")[0].value);
	append("Email address(es)", document.getElementsByName("email_to")[0].value);
	append("Include results in email", document.getElementsByName("email_sendresults")[0].checked);
	var e = document.getElementsByName("email_format")[0]; // (Email Format) (inline, as PDF, as CSV)
	append("(Email format)", e.options[e.selectedIndex].value);
	append("File name of the shell script to run", document.getElementsByName("script_filename")[0].value);
	append("Start Stream capture", document.getElementsByName("makestreams_isenabled")[0].checked);
}

function acquireKeyIndicatorSearch(){
	filename = document.getElementsByName("search-name")[0].value + TSV_EXT
	append("URL", URL);
	
	// Key Indicator Search
	append("Search Name", document.getElementsByName("search-name")[0].value);
	var e = document.getElementsByName("app")[0];
	append("Destination App", e.options[e.selectedIndex].innerHTML);
	append("Title", document.getElementsByName("title")[0].value);
	append("Sub-title", document.getElementsByName("sub-title")[0].value);
	append("Search", document.getElementsByName("search")[0].value);
	append("Drilldown URL", document.getElementsByName("drilldown-uri")[0].value);
	
	// Acceleration
	append("Schedule", document.getElementsByName("schedule")[0].checked);
	append("Cron Schedule", document.getElementsByName("cron-schedule")[0].value);
	
	// Fields
	append("Value", document.getElementsByName("value-field")[0].value);
	append("Delta", document.getElementsByName("delta-field")[0].value);
	
	// Rendering Options
	append("Threshold", document.getElementsByName("threshold")[0].value);
	append("Value suffix", document.getElementsByName("value-suffix")[0].value);
	append("Invert", document.getElementsByName("invert")[0].checked);
}

function acquireSavedSearch(){
	filename = document.getElementsByClassName("ManagerPageTitle")[0].innerHTML + TSV_EXT
	append("URL", URL);
	
	// Search
	append("Search", document.getElementById("search_id").value);
	append("Description", document.getElementById("description_id").value);
	var arr = document.getElementsByName("dispatchAs");
	for (var i = 0, len = arr.length; i < len; i++) {
	  if(arr[i].checked){append("Run as", arr[i].value);};
	};
	
	// Time Range
	append("Earliest", document.getElementById("dispatch.earliest_time_id").value);
	append("Latest", document.getElementById("dispatch.earliest_time_id").value);
	
	// Acceleration
	append("Accelerate this search", document.getElementById("auto_summarize_id").checked);
	var e = document.getElementById("auto_summarize.dispatch.earliest_time_id");
	append("Summary range", e.options[e.selectedIndex].innerHTML);
	
	// Schedule and Alert
	append("Schedule this alert", document.getElementById("is_scheduled_id").checked);
	var e = document.getElementById("spl-ctrl_schedType_id");
	append("Search", document.getElementById("cron_schedule_id").value);
	append("Search", document.getElementById("schedule_window_id").value);
	append("Schedule window", e.options[e.selectedIndex].innerHTML);
	var e = document.getElementById("schedule_priority_id");
	append("Schedule priority", e.options[e.selectedIndex].innerHTML);
	
	// Alert
	var e = document.getElementById("alert_type_id");
	append("Condition", e.options[e.selectedIndex].innerHTML);
	var e = document.getElementById("alert.digest_mode_id");
	append("Alert mode", e.options[e.selectedIndex].innerHTML);
	append("Throttling", document.getElementById("alert.suppress_id").checked);
	append("(Throttling time value)", document.getElementById("alert_suppress_period_value_id").value);
	var e = document.getElementById("alert_suppress_period_unit_id");
	append("(Throttling time scale)", e.options[e.selectedIndex].innerHTML);
	var e = document.getElementById("alertexpiration_id");
	append("Expiration", e.options[e.selectedIndex].innerHTML);
	var e = document.getElementById("alert.severity_id");
	append("Severity", e.options[e.selectedIndex].innerHTML);
	
	// Alert Actions
	append("Send email", document.getElementById("spl-ctrl_email_enable_id").checked);
	append("To", document.getElementById("action.email.to_id").value);
	append("CC", document.getElementById("action.email.cc_id").value);
	append("BCC", document.getElementById("action.email.bcc_id").value);
	append("Add to RSS", document.getElementById("spl-ctrl_rss_enable_id").checked);
	append("Run a script", document.getElementById("spl-ctrl_script_enable_id").checked);
	append("File name of the shell script to run", document.getElementById("action.script.filename_id").value);
	append("List in Triggered Alerts", document.getElementById("alert.track_id").checked);
	
	// Summary Indexing
	append("Summary indexing", document.getElementById("spl-ctrl_summary_index_id").checked);
	var e = document.getElementById("action.summary_index._name_id");
	append("Select the summary index", e.options[e.selectedIndex].innerHTML);
	var arr = document.getElementsByClassName("widget fieldmapping");
	for (var i = 0, len = arr.length; i < len; i++) {
		if(i != 1){ // Element 1 is empty
			startKey("(Index field " + String(i) + ")");
			valueOnly(arr[i].getElementsByClassName("fieldmapping left")[0].value);
			valueOnly(arr[i].getElementsByClassName("fieldmapping right")[0].value);
			endKey();
		}
	};
}

function acquireSwimlaneSearch(){
	filename = document.getElementsByName("search-name")[0].value + TSV_EXT
	append("URL", URL);
	
	// Entity Investigator Search
	append("Search Name", document.getElementsByName("search-name")[0].value);
	var e = document.getElementsByName("app")[0];
	append("Destination App", e.options[e.selectedIndex].innerHTML);
	append("Title", document.getElementsByName("title")[0].value);
	append("Search", document.getElementsByName("search")[0].value);
	append("Drilldown Search", document.getElementsByName("drilldown-search")[0].value);
	var e = document.getElementsByName("color")[0];
	append("Color", e.options[e.selectedIndex].innerHTML);
	var e = document.getElementsByName("entity_type")[0];
	append("Entity type", e.options[e.selectedIndex].innerHTML);
	startKey("Constraint Fields");
	var arr = document.getElementsByClassName("tm-tag");
	for (var i = 0, len = arr.length; i < len; i++) {
	  valueOnly(arr[i].childNodes[0].innerHTML);
	};
	endKey();
}

function acquireView(){
	var extension = ".xml"
	var viewType = document.getElementById("eai:type_id").value;
	if(viewType != "XML"){extension = viewType}
	filename = document.getElementsByClassName("ManagerPageTitle")[0].innerHTML + extension
	startKey(document.getElementById("eai:data_id").value);
}

function acquire(){
	data = "";
	if(URL.includes("SplunkEnterpriseSecuritySuite/correlation_search_edit")){acquireCorrelationSearch();};
	if(URL.includes("SplunkEnterpriseSecuritySuite/ess_key_indicator_edit")){acquireKeyIndicatorSearch();};
	if(URL.includes("SplunkEnterpriseSecuritySuite/saved/searches")){acquireSavedSearch();};
	if(URL.includes("SplunkEnterpriseSecuritySuite/ess_swimlane_edit")){acquireSwimlaneSearch();};
	if(URL.includes("SplunkEnterpriseSecuritySuite/data/ui/views")){acquireView();};
}

// Save data as file
function destroyClickedElement(event){document.body.removeChild(event.target);}
function saveTextAsFile(){
    var textToSaveAsURL = window.URL.createObjectURL(new Blob([data], {type:"text/plain"}));

    var downloadLink = document.createElement("a");
    downloadLink.download = filename;
    downloadLink.innerHTML = "Download File";
    downloadLink.href = textToSaveAsURL;
    downloadLink.onclick = destroyClickedElement;
    downloadLink.style.display = "none";
    document.body.appendChild(downloadLink);

    downloadLink.click();
}

function doTheThing(){
	acquire();
	saveTextAsFile();
}

doTheThing()
// Splunk Rule Downloader
// Written by Tyler Frederick (tyler.frederick@securityriskadvisors.com)
// Version 1.4, 05/30/2017
// 1.3 - Initial Release
// 1.4 - Add support for Key Indicators

// TSV Data
var tsv;
var filename;

// TSV Creator
function append(key, value){tsv = tsv + key + "\t" + String(value) + "\r\n";}

// For keys with multiple values
function startKey(key){tsv = tsv + key;}
function valueOnly(value){tsv = tsv + "\t" + String(value)}
function endKey(){tsv = tsv + "\r\n"}

function acquireCorrelationSearch(){
	filename = document.getElementsByName("name")[0].value + ".tsv"

	// URL
	append("URL", window.location.href);

	// Correlation Search
	append("Search Name", document.getElementsByName("name")[0].value); // Search Name*
	append("Application Context", document.getElementsByName("namespace")[0].value); // Application Context
	append("Description", document.getElementsByName("description")[1].value); // Description
	append("Search", document.getElementsByName("search")[0].value); // Search*

	// Time Range
	append("Start time", document.getElementsByName("start_time")[0].value); // Start time
	append("End time", document.getElementsByName("end_time")[0].value); // End time
	append("Cron Schedule", document.getElementsByName("cron_schedule")[0].value); // Cron Schedule*
	var e = document.getElementsByName("realtime_schedule_isenabled")[0]; // Scheduling
	append("Scheduling", e.options[e.selectedIndex].innerHTML);

	// Throttling
	append("Window Duration", document.getElementsByName("duration")[0].value); // Window Duration
	var arr = document.getElementsByClassName("tm-tag"); // Fields to group by
	startKey("Fields to group by");
	for (var i = 0, len = arr.length; i < len; i++) {
	  valueOnly(arr[i].childNodes[0].innerHTML);
	};
	endKey();

	// Notable Event
	append("Create notable event", document.getElementsByName("notable_isenabled")[0].checked); // Create notable event
	append("Title", document.getElementsByName("rule_title")[0].value); // Title
	append("Description", document.getElementsByName("rule_description")[0].value); // Description
	var e = document.getElementsByName("domain")[0]; // Security Domain
	if(e.selectedIndex != -1) {
		append("Security Domain", e.options[e.selectedIndex].value);
	};
	var e = document.getElementsByName("severity")[0]; // Severity
	append("Severity", e.options[e.selectedIndex].value);
	var e = document.getElementsByName("default_owner")[0]; // Defaut Owner
	append("Default Owner", e.options[e.selectedIndex].innerHTML);
	var e = document.getElementsByName("default_status")[0]; // Default Status
	append("Default Status", e.options[e.selectedIndex].innerHTML);
	append("Drill-down name", document.getElementsByName("drilldown_name")[0].value); // Drill-down name
	append("Drill-down search", document.getElementsByName("drilldown_search")[0].value); // Drill-down search
	append("Drill-down earliest offset", document.getElementsByName("drilldown_earliest_offset")[0].value); // Drill-down earliest offset
	append("Drill-down latest offset", document.getElementsByName("drilldown_latest_offset")[0].value); // Drill-down latest offset

	// Risk Scoring
	append("Create risk modifier", document.getElementsByName("risk_isenabled")[0].checked); // Create risk modifier
	append("Score", document.getElementsByName("risk_score")[0].value); // Score*
	append("Risk object field", document.getElementsByName("risk_object")[0].value); // Risk object field*
	append("Risk object type", document.getElementsByClassName("select2-chosen")[0].innerHTML); // Risk object type*

	// Actions
	append("Include in RSS feed", document.getElementsByName("rss_isenabled")[0].checked); // Include in RSS feed
	append("Send email", document.getElementsByName("email_isenabled")[0].checked); // Send email
	append("Email subject", document.getElementsByName("email_subject")[0].value); // Email subject*
	append("Email address(es)", document.getElementsByName("email_to")[0].value); // Email address(es)*
	append("Include results in email", document.getElementsByName("email_sendresults")[0].checked); // Include results in email
	var e = document.getElementsByName("email_format")[0]; // (Email Format) (inline, as PDF, as CSV)
	append("(Email format)", e.options[e.selectedIndex].value);
	append("File name of the shell script to run", document.getElementsByName("script_filename")[0].value); // File name of the shell script to run
	append("Start Stream capture", document.getElementsByName("makestreams_isenabled")[0].checked); // Start Stream capture
}

function acquireKeyIndicatorSearch(){
	filename = document.getElementsByName("search-name")[0].value + ".tsv"
	
	// URL
	append("URL", window.location.href);
	
	// Key Indicator Search
	append("Search Name", document.getElementsByName("search-name")[0].value); // Search Name*
	var e = document.getElementsByName("app")[0]; // Destination App
	append("Destination App", e.options[e.selectedIndex].innerHTML);
	append("Title", document.getElementsByName("title")[0].value); // Title*
	append("Sub-title", document.getElementsByName("sub-title")[0].value); // Sub-title
	append("Search", document.getElementsByName("search")[0].value); // Search*
	append("Drilldown URL", document.getElementsByName("drilldown-uri")[0].value); // Drilldown URL
	
	// Acceleration
	append("Schedule", document.getElementsByName("schedule")[0].checked); // Schedule
	append("Cron Schedule", document.getElementsByName("cron-schedule")[0].value); // Cron Schedule*
	
	// Fields
	append("Value", document.getElementsByName("value-field")[0].value); // Value*
	append("Delta", document.getElementsByName("delta-field")[0].value); // Delta
	
	// Rendering Options
	append("Threshold", document.getElementsByName("threshold")[0].value); // Threshold
	append("Value suffix", document.getElementsByName("value-suffix")[0].value); // Value suffix
	append("Invert", document.getElementsByName("invert")[0].checked); // Invert
}

function acquire(){
	tsv = "";
	switch(document.getElementsByTagName("h1")[0].innerHTML) {
    case "Correlation Search":
        acquireCorrelationSearch()
        break;
    case "Key Indicator Search":
        acquireKeyIndicatorSearch()
        break;
    default:
        break;
	}
}

// Save tsv as file
function destroyClickedElement(event){document.body.removeChild(event.target);}
function saveTextAsFile(){
    //inputTextToSave--> the text area from which the text to save is taken from
    var textToSave = tsv
    var textToSaveAsBlob = new Blob([textToSave], {type:"text/plain"});
    var textToSaveAsURL = window.URL.createObjectURL(textToSaveAsBlob);
    //inputFileNameToSaveAs-->The text field in which the user input for the desired file name is input into.
    var fileNameToSaveAs = filename

    var downloadLink = document.createElement("a");
    downloadLink.download = fileNameToSaveAs;
    downloadLink.innerHTML = "Download File";
    downloadLink.href = textToSaveAsURL;
    downloadLink.onclick = destroyClickedElement;
    downloadLink.style.display = "none";
    document.body.appendChild(downloadLink);

    downloadLink.click();
}

// Export Button onClick()
function doTheThing(){
	acquire();
	saveTextAsFile();
}

doTheThing()
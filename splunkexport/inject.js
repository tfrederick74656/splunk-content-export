function append(e,t){tsv=tsv+e+"\t"+String(t)+"\r\n"}function startKey(e){tsv+=e}function valueOnly(e){tsv=tsv+"\t"+String(e)}function endKey(){tsv+="\r\n"}function acquireCorrelationSearch(){filename=document.getElementsByName("name")[0].value+".tsv",append("URL",window.location.href),append("Search Name",document.getElementsByName("name")[0].value),append("Application Context",document.getElementsByName("namespace")[0].value),append("Description",document.getElementsByName("description")[1].value),append("Search",document.getElementsByName("search")[0].value),append("Start time",document.getElementsByName("start_time")[0].value),append("End time",document.getElementsByName("end_time")[0].value),append("Cron Schedule",document.getElementsByName("cron_schedule")[0].value);var e=document.getElementsByName("realtime_schedule_isenabled")[0];append("Scheduling",e.options[e.selectedIndex].innerHTML),append("Window Duration",document.getElementsByName("duration")[0].value);var t=document.getElementsByClassName("tm-tag");startKey("Fields to group by");for(var n=0,a=t.length;n<a;n++)valueOnly(t[n].childNodes[0].innerHTML);endKey(),append("Create notable event",document.getElementsByName("notable_isenabled")[0].checked),append("Title",document.getElementsByName("rule_title")[0].value),append("Description",document.getElementsByName("rule_description")[0].value),-1!=(e=document.getElementsByName("domain")[0]).selectedIndex&&append("Security Domain",e.options[e.selectedIndex].value),append("Severity",(e=document.getElementsByName("severity")[0]).options[e.selectedIndex].value),append("Default Owner",(e=document.getElementsByName("default_owner")[0]).options[e.selectedIndex].innerHTML),append("Default Status",(e=document.getElementsByName("default_status")[0]).options[e.selectedIndex].innerHTML),append("Drill-down name",document.getElementsByName("drilldown_name")[0].value),append("Drill-down search",document.getElementsByName("drilldown_search")[0].value),append("Drill-down earliest offset",document.getElementsByName("drilldown_earliest_offset")[0].value),append("Drill-down latest offset",document.getElementsByName("drilldown_latest_offset")[0].value),append("Create risk modifier",document.getElementsByName("risk_isenabled")[0].checked),append("Score",document.getElementsByName("risk_score")[0].value),append("Risk object field",document.getElementsByName("risk_object")[0].value),append("Risk object type",document.getElementsByClassName("select2-chosen")[0].innerHTML),append("Include in RSS feed",document.getElementsByName("rss_isenabled")[0].checked),append("Send email",document.getElementsByName("email_isenabled")[0].checked),append("Email subject",document.getElementsByName("email_subject")[0].value),append("Email address(es)",document.getElementsByName("email_to")[0].value),append("Include results in email",document.getElementsByName("email_sendresults")[0].checked),append("(Email format)",(e=document.getElementsByName("email_format")[0]).options[e.selectedIndex].value),append("File name of the shell script to run",document.getElementsByName("script_filename")[0].value),append("Start Stream capture",document.getElementsByName("makestreams_isenabled")[0].checked)}function acquireKeyIndicatorSearch(){filename=document.getElementsByName("search-name")[0].value+".tsv",append("URL",window.location.href),append("Search Name",document.getElementsByName("search-name")[0].value);var e=document.getElementsByName("app")[0];append("Destination App",e.options[e.selectedIndex].innerHTML),append("Title",document.getElementsByName("title")[0].value),append("Sub-title",document.getElementsByName("sub-title")[0].value),append("Search",document.getElementsByName("search")[0].value),append("Drilldown URL",document.getElementsByName("drilldown-uri")[0].value),append("Schedule",document.getElementsByName("schedule")[0].checked),append("Cron Schedule",document.getElementsByName("cron-schedule")[0].value),append("Value",document.getElementsByName("value-field")[0].value),append("Delta",document.getElementsByName("delta-field")[0].value),append("Threshold",document.getElementsByName("threshold")[0].value),append("Value suffix",document.getElementsByName("value-suffix")[0].value),append("Invert",document.getElementsByName("invert")[0].checked)}function acquire(){switch(tsv="",document.getElementsByTagName("h1")[0].innerHTML){case"Correlation Search":acquireCorrelationSearch();break;case"Key Indicator Search":acquireKeyIndicatorSearch()}}function destroyClickedElement(e){document.body.removeChild(e.target)}function saveTextAsFile(){var e=tsv,t=new Blob([e],{type:"text/plain"}),n=window.URL.createObjectURL(t),a=filename,l=document.createElement("a");l.download=a,l.innerHTML="Download File",l.href=n,l.onclick=destroyClickedElement,l.style.display="none",document.body.appendChild(l),l.click()}function doTheThing(){acquire(),saveTextAsFile()}var tsv,filename;doTheThing();
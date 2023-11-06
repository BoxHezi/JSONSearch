var template =
  "<td><a href='$url' target='_blank'>$cveId</a></td><td>$cvss</td><td>$desc</td><td>$published</td>";
var resultLimit = 200; // declare a variable to limit search results

function parseDesc(content) {
  return content.replace("<", "&lt;").replace(">", "&gt;").replace(/\'/g, '"');
}

function getCVSS(cve) {
  if ("v31score" in cve) {
    return cve.v31score;
  } else if ("v30score" in cve) {
    return cve.v30score;
  } else if ("v2score" in cve) {
    return cve.v2score;
  }
  return "N/A";
}

function updateDisplay(data) {
  document.getElementById("result-body").innerHTML = ""; // clear the table
  for (const [k, v] of Object.entries(data)) {
    let tr = document.createElement("tr");
    let content = template
      .replace("$url", v.url)
      .replace("$cveId", v.id)
      .replace("$cvss", getCVSS(v)) // get cvss score for each cve
      .replace("$desc", parseDesc(v.descriptions[0].value))
      .replace("$published", v.published.replace("T", " "));
    tr.innerHTML = content;
    let tbodyContent = document.getElementById("result-body");
    tbodyContent.appendChild(tr);
  }
}

function doSearch(value) {
  const toSearch = value.toLowerCase();
  let filtered = []; // list to store filtered result
  for (const [k, v] of Object.entries(window.data)) {
    if (
      v.id.toLowerCase().includes(toSearch) ||
      v.descriptions[0].value.toLowerCase().includes(toSearch) ||
      v.published.toLowerCase().includes(toSearch)
    ) {
      filtered.push(window.data[k]);
    }
  }
  updateDisplay(filtered);
}

function parseInputFile(file) {
  const reader = new FileReader();
  reader.readAsText(file);
  reader.onloadend = function (e) {
    let result = e.target.result;
    try {
      result = JSON.parse(result);
    } catch (err) {
      console.log(err);
    }
    if ("cve" in result) {
      window.data = result.cve;
    } else {
      window.data = result;
    }
    updateDisplay(window.data);
  };
}

var template =
  "<td><a href='$url' target='_blank'>$cveId</a></td><td>$cvss</td><td>$desc</td><td>$published</td>";
var resultLimit = 200; // declare a variable to limit search results

function parseDesc(content) {
  return content.replace("<", "&lt;").replace(">", "&gt;").replace(/\'/g, '"');
}

function getDescByLang(desc, langCode = "en") {
  /**
   * get description by language code
   * if no provided language code is found, return the first description
   */
  result = desc[0].value; // default value if no langCode is found
  for (const temp of desc) {
    if ("lang" in temp && temp["lang"] === langCode) {
      result = temp.value;
      break;
    }
  }
  return result;
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
      .replace("$cvss", getCVSS(v).toFixed(1)) // get cvss score for each cve
      .replace("$desc", parseDesc(getDescByLang(v.descriptions)))
      .replace("$published", v.published.replace("T", " "));
    tr.innerHTML = content;
    let tbodyContent = document.getElementById("result-body");
    tbodyContent.appendChild(tr);
  }
}

function doSearch(value) {
  // TODO: add negative match
  const words = value.toLowerCase().split(" ");
  regex = "";
  let filtered = []; // list to store filtered result
  for (const w of words) {
    regex += "(?=.*" + w + ")";
  }
  for (const [k, v] of Object.entries(window.data)) {
    const testStr =
      v.id.toLowerCase() + getDescByLang(v.descriptions).toLowerCase();
    if (testStr.match(regex)) {
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
      return;
    }
    if ("cve" in result) {
      window.data = result.cve;
    } else {
      window.data = result;
    }
    updateDisplay(window.data);
  };
}

// window.data: store all information read from json file

var template =
  "<td><a href='$url' target='_blank'>$cveId</a></td><td>$cvss</td><td>$desc</td><td>$published</td>";
var resultLimit = 200; // declare a variable to limit search results

function parseDesc(content) {
  return content.replace("<", "&lt;").replace(">", "&gt;").replace(/\'/g, '"');
}

/**
 * Retrieves a description from an array of descriptions based on a specified language code.
 *
 * @param {Array} desc - An array of description objects. Each object should have a "lang" property specifying the language and a "value" property containing the description.
 * @param {string} [langCode="en"] - The language code to match. Defaults to "en" (English) if not provided.
 * @returns {string} The value of the first description that matches the provided language code, or the value of the first description in the array if no match is found.
 */
function getDescByLang(desc, langCode = "en") {
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

/**
 * Generates a regular expression based on the provided search terms.
 *
 * @param {Array} words - An array of search terms. If a term starts with "-", it is considered a negative match.
 * @returns {string} A regular expression that matches any string containing all the search terms (excluding the negative matches).
 */
function generateRegex(words) {
  let regex = "";
  let negativeMatch = [];

  for (const w of words) {
    if (w[0] === "-") {
      negativeMatch.push(w.substring(1));
    } else {
      regex += "(?=.*" + w + ")";
    }
  }
  if (negativeMatch.length > 0) {
    regex += "(^((?!("; // (^((?!(n)).)*$)
    for (let i = 0; i < negativeMatch.length; i++) {
      regex += negativeMatch[i];
      if (i != negativeMatch.length - 1) {
        regex += "|";
      }
    }
    regex += ")).)*$)";
  }
  return regex;
}

/**
 * Filters the provided data based on the provided regular expression.
 *
 * @param {string} regex - A regular expression used to filter the data.
 * @param {Object} data - The data to be filtered. Each entry should have an "id" property and a "descriptions" property. Default to window.data
 * @returns {Array} An array containing the entries in the data that match the regular expression.
 */
function filterData(regex, data = window.data) {
  let filtered = [];
  for (const [k, v] of Object.entries(data)) {
    const testStr =
      v.id.toLowerCase() + getDescByLang(v.descriptions).toLowerCase();
    if (testStr.match(regex)) {
      filtered.push(data[k]);
    }
  }
  return filtered;
}

/**
 * Performs a search operation on window.data based on the provided search terms and updates the display with the search results.
 *
 * @param {string} value - A string containing the search terms. If a term starts with "-", it is considered a negative match.
 */
function doSearch(value) {
  const regex = generateRegex(value.toLowerCase().split(" "));
  const filtered = filterData(regex);
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

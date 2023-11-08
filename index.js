var resultLimit = 200; // declare a variable to limit search results

/**
 * Replaces certain characters in a string with their HTML entities.
 *
 * @param {string} content - The string to be parsed.
 * @returns {string} The parsed string.
 */
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

/**
 * This function formats the CVSS score of a CVE item.
 *
 * @param {Object} cve - The CVE item object. This object should have a 'score' property that is an array of two elements.
 * @returns {string} A string representing the CVSS score in the format "X - Y.Y", where X is the first element of the 'score' array and Y.Y is the second element of the 'score' array, rounded to one decimal place.
 */
function getCVSS(cve) {
  const score = cve.score;
  return score[0] + " - " + score[1].toFixed(1);
}

/**
 * Get the severity of a cve
 *
 * @param {Object} cve - The CVE object
 * @returns {string} - The severity of the given CVE
 */
function getSeverity(cve) {
  return cve.score[2];
}

/**
 * Creates a span element with a class based on the severity level.
 *
 * @param {string} severity - The severity level of a CVE item.
 * @returns {Object} A span element with a class corresponding to the severity level and the inner text set to the severity level.
 */
function parseSeverity(severity) {
  let span = document.createElement("span");
  span.classList.add("alert");
  if (severity == "CRITICAL" || severity == "HIGH") {
    span.classList.add("alert-danger");
  } else if (severity == "MEDIUM") {
    span.classList.add("alert-warning");
  } else {
    span.classList.add("alert-success");
  }
  span.innerText = severity;
  return span;
}

/**
 * Generates a table row with the provided data.
 *
 * @param {Object} data - The data to be displayed in the table row. The object should have properties: url, id, score, severity, descriptions, and published.
 * @returns {string} A string representing a table row with the provided data.
 */
function generateTableRow(data) {
  return `
    <td><a href="${data.url}" target="_blank">${data.id}</a></td>
    <td>${getCVSS(data)}</td>
    <td>${parseSeverity(getSeverity(data)).outerHTML}</td>
    <td>${parseDesc(getDescByLang(data.descriptions))}</td>
    <td>${data.published.split("T")[0]}</td>
  `;
}

/**
 * Updates the display with the provided data.
 *
 * @param {Object} data - The data to be displayed. Each entry should have an "id" property and a "descriptions" property.
 */
function updateDisplay(data) {
  document.getElementById("result-thead").style.display = "";
  document.getElementById("result-tbody").innerHTML = ""; // clear the table
  for (const [k, v] of Object.entries(data)) {
    let tr = document.createElement("tr");
    tr.innerHTML = generateTableRow(v);
    document.getElementById("result-tbody").appendChild(tr);
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
    regex += "(^((?!("; // (^((?!(n[0]|n[1])).)*$)
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

/**
 * Parses an input file and updates the display with the parsed data.
 *
 * @param {File} file - The input file to be parsed.
 */
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

var resultLimit = 200; // declare a variable to limit search results
var allData = []; // all data
var displayData = []; // current display data

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
    <td style='text-align: justify'>${parseDesc(
      getDescByLang(data.descriptions)
    )}</td>
    <td>${data.published.split("T")[0]}</td>
  `;
}

/**
 * Updates the display with the provided data.
 *
 * @param {Object} data - The data to be displayed. Each entry should have an "id" property and a "descriptions" property.
 */
function updateDisplay(data) {
  displayData = [];
  document.getElementById("result-thead").style.display = "";
  document.getElementById("result-tbody").innerHTML = ""; // clear the table
  for (const d of data) {
    let tr = document.createElement("tr");
    tr.title = d.sourceIdentifier;
    tr.innerHTML = generateTableRow(d);
    document.getElementById("result-tbody").appendChild(tr);
    displayData.push(d);
  }
}

/**
 * Generates a regular expression based on the provided search terms.
 *
 * @param {Array} words - An array of search terms. If a term starts with "-", it is considered a negative match.
 * @returns {string} A regular expression that matches any string containing all the search terms (excluding the negative matches).
 */
function generateRegex(words) {
  let positiveMatch = [];
  let negativeMatch = [];

  for (const w of words) {
    let word = w.replace(/[.*+?^${}()|\[\]\\]/g, "\\$&");
    if (w[0] === "-") {
      negativeMatch.push(word.substring(1));
    } else {
      positiveMatch.push(word);
    }
  }

  /* (?=.*w0)(?=.*w2) */
  let regex = positiveMatch.map((s) => "(?=.*" + s + ")").join("");
  if (negativeMatch.length > 0) {
    /* (^((?!(w0|w1)).)*$) */
    regex += "(^((?!(" + negativeMatch.join("|") + ")).)*$)";
  }
  // console.log(regex);
  return regex;
}

/**
 * Filters the provided data based on a regular expression.
 *
 * @param {RegExp} regex - The regular expression to match against.
 * @param {Array} [data=allData] - The data to filter. Defaults to the global `allData` array if not provided.
 * @returns {Array} An array containing only the data items that match the regular expression. Each item in the array is an object that includes an 'id' and 'descriptions'.
 */
function filterData(regex, data = allData) {
  let filtered = [];
  for (const d of data) {
    const testStr =
      d.id.toLowerCase() + getDescByLang(d.descriptions).toLowerCase();
    if (testStr.match(regex)) {
      filtered.push(d);
    }
  }
  return filtered;
}

/**
 * Performs a search operation on the data.
 *
 * @param {string} value - The search term(s) to be used. Multiple terms can be separated by spaces. If a term starts with "-", it is considered a negative match.
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
    for (const [_, v] of Object.entries(result)) {
      allData.push(v);
    }
    updateDisplay(allData);
  };
}

/**
 * Sorting Function
 */

var sortIconASC = "bi-sort-up"; // ASC Order
var sortIconDESC = "bi-sort-down"; // DESC Order
var sortStatus = 0; // 0: no sorting, 1: DESC, 2: ASC
var lastSortTarget = "";
var unsortedData = [];

/**
 * Removes the sort icon from the specified element.
 *
 * @param {HTMLElement} iconElem - The HTML element from which to remove the sort icon.
 */
function removeSortIcon(iconElem) {
  try {
    iconElem.classList.remove(sortIconDESC);
    iconElem.classList.remove(sortIconASC);
  } catch {}
}

/**
 * Updates the sort status and returns the corresponding sort icon class.
 *
 * @returns {string|null} The class of the sort icon corresponding to the updated sort status, or null if the sort status is 0.
 */
function updateSortStatus() {
  sortStatus = (sortStatus + 1) % 3;
  return sortStatus === 1
    ? sortIconDESC
    : sortStatus === 2
    ? sortIconASC
    : null;
}

/**
 * Sets the sort icon for the specified element.
 *
 * @param {HTMLElement} iconElem - The HTML element for which to set the sort icon.
 * @param {string} sortClass - The class of the sort icon to set.
 */
function setSortIcon(iconElem, sortClass) {
  removeSortIcon(iconElem);
  if (sortClass) {
    iconElem.classList.add(sortClass);
  }
}

/**
 * Updates the sort icon for the specified sort target.
 *
 * @param {string} sortTarget - The sort target for which to update the sort icon.
 */
function updateSortIcon(sortTarget) {
  if (sortTarget !== lastSortTarget) {
    sortStatus = 0;
  }
  let theads = document.querySelectorAll("th");
  for (let t of theads) {
    let iconElem = t.querySelector("i");
    if (iconElem) {
      if (t.innerText === sortTarget) {
        const sortClass = updateSortStatus();
        setSortIcon(iconElem, sortClass);
        lastSortTarget = sortTarget;
      } else {
        removeSortIcon(iconElem);
      }
    }
  }
}

/**
 * Sorts the specified dataset based on the specified sort field.
 *
 * @param {Array} dataset - The dataset to sort.
 * @param {string} sortField - The field to sort by.
 * @returns {Array} The sorted dataset.
 */
function sortData(dataset, sortField) {
  // sortStatus: 1: DESC, 2: ASC
  return dataset.sort((a, b) => {
    let aValue, bValue;
    if (sortField === "CVE") {
      aValue = a.id.split("-");
      bValue = b.id.split("-");
      aValue = parseInt(aValue[1] + aValue[2]);
      bValue = parseInt(bValue[1] + bValue[2]);
    } else if (sortField === "CVSS") {
      aValue = a.score[1];
      bValue = b.score[1];
    } else if (sortField === "Published Date") {
      aValue = Date.parse(a.published);
      bValue = Date.parse(b.published);
    }

    return sortStatus === 1 ? bValue - aValue : aValue - bValue;
  });
}

/**
 * Performs a sort operation based on the event target's inner text.
 *
 * @param {Event} e - The event object.
 */
function doSort(e) {
  if (sortStatus === 0 || unsortedData.length !== displayData.length) {
    unsortedData = displayData;
  }
  const sortTarget = e.target.innerText;
  updateSortIcon(sortTarget);
  const clone = structuredClone(displayData); // create a copy
  if (sortStatus === 0) {
    updateDisplay(unsortedData);
  } else {
    updateDisplay(sortData(clone, sortTarget));
  }
}

// add event listener to table headers, in order to enable sorting function
let theads = document.querySelectorAll("th");
for (let t of theads) {
  if (t.querySelector("i")) {
    // if there is <i /> tag insider the <th>, the column has sorting function
    t.addEventListener("click", doSort);
  }
}

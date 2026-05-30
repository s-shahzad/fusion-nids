(() => {
  const DEFAULT_ALGORITHMS = [
    { id: "logistic_regression", label: "Logistic Regression", available: true },
    { id: "decision_tree", label: "Decision Tree", available: true },
    { id: "random_forest", label: "Random Forest", available: true },
    { id: "svm_rbf", label: "SVM (RBF)", available: true },
    { id: "knn", label: "K-Nearest Neighbors", available: true },
    { id: "naive_bayes", label: "Gaussian Naive Bayes", available: true },
    { id: "gradient_boosting", label: "Gradient Boosting", available: true },
    { id: "xgboost", label: "XGBoost", available: false },
  ];

  const trainForm = document.getElementById("evcsTrainForm");
  const predictForm = document.getElementById("evcsPredictForm");
  const algorithmsList = document.getElementById("algorithmsList");
  const algorithmsStatus = document.getElementById("algorithmsStatus");
  const trainStatus = document.getElementById("trainStatus");
  const predictStatus = document.getElementById("predictStatus");
  const trainResults = document.getElementById("trainResults");
  const predictResults = document.getElementById("predictResults");

  const trainFiles = document.getElementById("trainFiles");
  const targetColumn = document.getElementById("targetColumn");
  const positiveLabels = document.getElementById("positiveLabels");
  const testSize = document.getElementById("testSize");
  const sampleRows = document.getElementById("sampleRows");
  const trainBtn = document.getElementById("trainBtn");

  const modelId = document.getElementById("modelId");
  const predictModelId = document.getElementById("predictModelId");
  const predictFiles = document.getElementById("predictFiles");
  const predictBtn = document.getElementById("predictBtn");

  const kpiDatasetRows = document.getElementById("kpiDatasetRows");
  const kpiFeatureCount = document.getElementById("kpiFeatureCount");
  const kpiBestModel = document.getElementById("kpiBestModel");

  const predRows = document.getElementById("predRows");
  const predThreat = document.getElementById("predThreat");
  const predBenign = document.getElementById("predBenign");

  const resultsTableBody = document.querySelector("#resultsTable tbody");
  const predictionTableBody = document.querySelector("#predictionTable tbody");

  const escapeHtml = (value) =>
    String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");

  const setStatus = (node, message, state = "") => {
    if (!node) return;
    node.textContent = message || "";
    if (state) node.dataset.state = state;
    else delete node.dataset.state;
  };

  const fileToBase64Payload = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = String(reader.result || "");
        const marker = result.indexOf(",");
        const contentBase64 = marker >= 0 ? result.slice(marker + 1) : "";
        if (!contentBase64) {
          reject(new Error(`Unable to read ${file.name}`));
          return;
        }
        resolve({ name: file.name, content_base64: contentBase64 });
      };
      reader.onerror = () => reject(new Error(`Unable to read ${file.name}`));
      reader.readAsDataURL(file);
    });

  const collectFiles = async (input) => {
    const fileList = Array.from(input?.files || []);
    if (!fileList.length) {
      throw new Error("Select at least one file");
    }
    const payloads = [];
    for (const file of fileList) {
      payloads.push(await fileToBase64Payload(file));
    }
    return payloads;
  };

  const parseCommaList = (value) =>
    String(value || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

  const selectedAlgorithms = () => {
    return Array.from(document.querySelectorAll("input[name='evcsAlgorithm']:checked"))
      .map((item) => String(item.value || "").trim())
      .filter(Boolean);
  };

  const renderAlgorithmSelector = (algorithms) => {
    if (!algorithmsList) return;
    const safeAlgorithms = Array.isArray(algorithms) && algorithms.length ? algorithms : DEFAULT_ALGORITHMS;

    algorithmsList.innerHTML = safeAlgorithms
      .map((algorithm, index) => {
        const available = Boolean(algorithm?.available);
        const checked = available && index < 4 ? "checked" : "";
        const disabled = available ? "" : "disabled";
        const stateLabel = available ? "" : " (unavailable on this server)";
        return `
          <label class="algo-item${available ? "" : " is-disabled"}">
            <input type="checkbox" name="evcsAlgorithm" value="${escapeHtml(algorithm.id)}" ${checked} ${disabled} />
            <span>${escapeHtml(algorithm.label)}${stateLabel}</span>
          </label>
        `;
      })
      .join("");
  };

  const apiJson = async (url, payload) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await response.json().catch(() => null);
    if (!response.ok || !data?.ok) {
      const message = data?.error || `Request failed (${response.status})`;
      throw new Error(message);
    }
    return data;
  };

  const renderTrainingResults = (payload) => {
    const training = payload?.training || {};
    const bestModel = training?.best_model || {};
    const rows = Array.isArray(training?.results) ? training.results : [];

    kpiDatasetRows.textContent = String(training?.dataset_rows ?? 0);
    kpiFeatureCount.textContent = String(training?.feature_count ?? 0);
    kpiBestModel.textContent = String(bestModel?.algorithm || "-");

    const modelToken = String(bestModel?.model_id || "");
    modelId.value = modelToken;
    predictModelId.value = modelToken;

    resultsTableBody.innerHTML = rows
      .map((row) => {
        if (row?.status !== "ok") {
          return `
            <tr>
              <td>${escapeHtml(row?.algorithm || row?.algorithm_id || "Unknown")}</td>
              <td>error</td>
              <td colspan="6">${escapeHtml(row?.error || "Execution failed")}</td>
            </tr>
          `;
        }
        const cm = Array.isArray(row?.confusion_matrix) ? JSON.stringify(row.confusion_matrix) : "-";
        return `
          <tr>
            <td>${escapeHtml(row?.algorithm || "-")}</td>
            <td>ok</td>
            <td>${escapeHtml(row?.accuracy ?? "-")}</td>
            <td>${escapeHtml(row?.precision ?? "-")}</td>
            <td>${escapeHtml(row?.recall ?? "-")}</td>
            <td>${escapeHtml(row?.f1_score ?? "-")}</td>
            <td>${escapeHtml(row?.auroc ?? "-")}</td>
            <td><code>${escapeHtml(cm)}</code></td>
          </tr>
        `;
      })
      .join("");

    trainResults.hidden = false;
  };

  const renderPredictionResults = (payload) => {
    const prediction = payload?.prediction || {};
    const counts = prediction?.predicted_counts || {};

    predRows.textContent = String(prediction?.rows_scored ?? 0);
    predThreat.textContent = String(counts?.threat ?? 0);
    predBenign.textContent = String(counts?.benign ?? 0);

    const rows = Array.isArray(prediction?.samples) ? prediction.samples : [];
    predictionTableBody.innerHTML = rows
      .map((row) => {
        const threatScore = row?.threat_score ?? "-";
        return `
          <tr>
            <td>${escapeHtml(row?.row_index ?? "-")}</td>
            <td>${escapeHtml(row?.label ?? row?.prediction ?? "-")}</td>
            <td>${escapeHtml(threatScore)}</td>
          </tr>
        `;
      })
      .join("");

    predictResults.hidden = false;
  };

  const loadFormats = async () => {
    if (window.location.protocol === "file:") {
      renderAlgorithmSelector(DEFAULT_ALGORITHMS);
      setStatus(algorithmsStatus, "Open this page via the Python server to run APIs.", "warn");
      return;
    }

    try {
      const response = await fetch("/api/evcs/formats", { headers: { Accept: "application/json" } });
      const payload = await response.json().catch(() => null);
      if (!response.ok || !payload?.ok) {
        throw new Error(payload?.error || `Unable to load formats (${response.status})`);
      }
      renderAlgorithmSelector(payload.algorithms);
      if (payload.ml_ready) {
        setStatus(algorithmsStatus, "ML backend ready. Choose algorithms and run training.", "ok");
      } else {
        setStatus(
          algorithmsStatus,
          `ML dependencies missing: ${(payload.missing_dependencies || []).join(", ") || "unknown"}`,
          "error"
        );
      }
    } catch (error) {
      renderAlgorithmSelector(DEFAULT_ALGORITHMS);
      setStatus(algorithmsStatus, String(error.message || error), "error");
    }
  };

  const handleTrain = async (event) => {
    event.preventDefault();
    trainResults.hidden = true;
    setStatus(trainStatus, "Preparing files...", "info");
    trainBtn.disabled = true;

    try {
      const files = await collectFiles(trainFiles);
      const algorithms = selectedAlgorithms();
      const labels = parseCommaList(positiveLabels.value);

      const payload = {
        files,
        algorithms,
        target_column: String(targetColumn.value || "").trim() || undefined,
        positive_labels: labels,
        test_size: Number(testSize.value || 0.2),
        sample_rows: sampleRows.value ? Number(sampleRows.value) : undefined,
      };

      setStatus(trainStatus, "Training models... this can take time on large datasets.", "info");
      const response = await apiJson("/api/evcs/train", payload);
      renderTrainingResults(response);
      const best = response?.training?.best_model?.algorithm || "best model";
      setStatus(trainStatus, `Training completed. Best model: ${best}.`, "ok");
    } catch (error) {
      setStatus(trainStatus, String(error.message || error), "error");
    } finally {
      trainBtn.disabled = false;
    }
  };

  const handlePredict = async (event) => {
    event.preventDefault();
    predictResults.hidden = true;
    setStatus(predictStatus, "Preparing files...", "info");
    predictBtn.disabled = true;

    try {
      const files = await collectFiles(predictFiles);
      const modelToken = String(predictModelId.value || "").trim();
      if (!modelToken) {
        throw new Error("Model ID is required");
      }

      setStatus(predictStatus, "Scoring uploaded samples...", "info");
      const response = await apiJson("/api/evcs/predict", {
        model_id: modelToken,
        files,
      });

      renderPredictionResults(response);
      setStatus(predictStatus, "Prediction completed.", "ok");
    } catch (error) {
      setStatus(predictStatus, String(error.message || error), "error");
    } finally {
      predictBtn.disabled = false;
    }
  };

  if (trainForm) trainForm.addEventListener("submit", handleTrain);
  if (predictForm) predictForm.addEventListener("submit", handlePredict);
  loadFormats();
})();

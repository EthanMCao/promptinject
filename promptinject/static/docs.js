"use strict";
(async () => {
  const status = document.getElementById("docs-status");
  try {
    const response = await fetch("/openapi.json");
    if (!response.ok)
      throw new Error(`Schema request failed (${response.status})`);
    const schema = await response.json();
    for (const [path, methods] of Object.entries(schema.paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        const section = document.createElement("section");
        section.className = "panel";
        const heading = document.createElement("h2");
        heading.textContent = `${method.toUpperCase()} ${path}`;
        const description = document.createElement("p");
        description.textContent = operation.summary || "";
        const details = document.createElement("pre");
        details.textContent = JSON.stringify(
          {
            parameters: operation.parameters || [],
            requestBody: operation.requestBody,
            responses: operation.responses,
          },
          null,
          2,
        );
        section.append(heading, description, details);
        document.getElementById("endpoints").append(section);
      }
    }
    document.getElementById("schemas").textContent = JSON.stringify(
      schema.components?.schemas || {},
      null,
      2,
    );
    status.textContent = `${Object.keys(schema.paths).length} documented paths · ${schema.info.title} ${schema.info.version}`;
  } catch (error) {
    status.textContent = error.message;
  }
})();

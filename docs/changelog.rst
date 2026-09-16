Changelog
=========

Version 4.0
-----------

Attack Flow 4.0 adds capabilities to help defenders create, enrich, and share
flows more effectively.

Create flows faster
~~~~~~~~~~~~~~~~~~~

* **AI-assisted flow generation** creates an editable starting flow from a PDF,
  URL, or plain-text incident report. See :doc:`AI Generation <generation>`.
* **Technique Inference Engine (TIE) recommendations** suggest related ATT&CK
  techniques as analysts build a path through an event.

Add operational context
~~~~~~~~~~~~~~~~~~~~~~~

* **Tags** let teams label flow objects with reusable, color-coded context such
  as detection status, remediation state, or an assigned task.
* **Mitigation and detection support** lets users attach defensive measures to
  actions and use recommended ATT&CK relationships as a starting point.
* **Additional frameworks** include MITRE ATLAS™, MITRE D3FEND™, and the MITRE
  Fight Fraud Framework™ alongside MITRE ATT&CK®. The Builder helps users keep
  flows aligned with their selected frameworks.
* **Banner markings** support common TLP markings, UNCLASSIFIED, CUI, and an
  optional group field so handling guidance remains attached to shared flows.

Communicate findings
~~~~~~~~~~~~~~~~~~~~

* **Expanded visualizations** are available through a shared interface for
  resizing, downloading, copying, and full-screen viewing. Available views
  include presentation, treemap, tactic table, timeline, matrix, and IOC table.
* **Presentation view** focuses on actions, conditions, and operators in a
  compact, horizontal layout designed for briefings.

For setup instructions and detailed guidance, see the :doc:`Builder <builder>`
and :doc:`Visualization <visualization>` documentation.

Version 3.2
-----------

Released May 2026.

* Updated the included MITRE ATT&CK content to version 19.1.
* Updated the included MITRE ATLAS content to version 5.6.1.
* Added TLP and other banner markings to preserve handling guidance when flows
  are shared.
* Added the OpenClaw example flow to the corpus.

Version 3.1
-----------

Released April 2026.

* Added support for MITRE ATLAS, MITRE D3FEND, and the MITRE Fight Fraud
  Framework.
* Added the ToolShell vulnerability example flow.
* Improved Builder reliability, including file saving, example-flow loading,
  sub-technique autocompletion, and object placement.

Version 3.0
-----------

Released July 2025.

* Introduced the redesigned Attack Flow Builder with improved interaction,
  visual fidelity, and performance.
* Added the v3 ``.afb`` file format and a migration path for v2 files.
* Added STIX import and command-line publishing support.
* Added embeddable, read-only flows and a splash-screen option to import STIX.
* Expanded Builder capabilities with ATT&CK tactic and technique autofill,
  rectangle selection, improved copy and paste, and additional visualizations.

Version 2.0
-----------

Released October 2022.

* Introduced a major Attack Flow Builder update focused on UI and performance
  improvements.

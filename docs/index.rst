Attack Flow |version|
=====================

Attack Flow is a language for describing how cyber adversaries combine and sequence
various offensive techniques to achieve their goals. The project helps defenders and
leaders understand how adversaries operate and improve their own defensive posture. This
project is created and maintained by the `MITRE Center for Threat-Informed
Defense <https://ctid.mitre-.org/>`__ in futherance of our mission to advance
the state of the art and the state of the practice in threat-informed defense
globally. The project is funded by our `research participants
<https://ctid.mitre.org/projects/attack-flow#participants-section>`__. The development of these usage guides has been shaped by direct input and feedback from our members—practitioners at large, international organizations with advanced cybersecurity programs. Their real-world experience and operational insights have grounded this work in practical, applicable guidance for defenders around the world.

.. note::

   This documentation site also publishes the PWNSAT-maintained fork of Attack Flow.
   The fork tracks upstream changes while adding SPARTA and ESA Space Shield support,
   sub-technique-aware autocompletion, custom observables for RF capture workflows,
   and UI customizations for the builder experience.

Space security frameworks
-------------------------

* **SPARTA 4.0.1**: `User guide <https://sparta.aerospace.org/resources/user-guide>`__,
  `release history <https://sparta.aerospace.org/resources/versions>`__, and
  `official STIX bundle <https://sparta.aerospace.org/download/STIX?f=latest>`__.
* **ESA Space Shield 0.3** (STIX collection, updated 2025-06-24):
  `documentation and matrix <https://spaceshield.esa.int/>`__ and
  `official STIX bundle <https://spaceshield.esa.int/stix/space-attack.json>`__.

Both frameworks are available in the builder's TTP selectors and wiki. Their
versions and documentation links are also displayed on the builder home screen.

.. toctree::
    :maxdepth: 1
    :caption: Contents

    overview
    introduction
    generation
    example_flows
    builder
    training
    usage_guides/index
    visualization
    language
    developers
    changelog

Notice
------

Â© 2025 MITRE. Approved for public release. Document number(s): CT0040.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.

This project makes use of ATT&CK®: `ATT&CK Terms of Use
<https://attack.mitre.org/resources/terms-of-use/>`__

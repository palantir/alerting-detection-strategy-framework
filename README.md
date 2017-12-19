# Alerting and Detection Strategies Framework

## About This Repository
This is a public version of the [Alerting and Detection Strategy (ADS) framework we use on the Incident Response Team at Palantir](https://www.medium.com/@palantir). 

This GitHub project provides the necessary building blocks for adopting this framework for organizations looking to improve the efficacy of their detection strategies. While there are operational security considerations around publicly acknowledging and documenting internal alerts, we hope these examples spur greater sharing and collaboration, inspire detection enhancements for other defenders, and ultimately increase the operational cost for attackers.

## ADS Framework
Prior to the development and adoption of the ADS framework, we faced major challenges with development of alerting strategies. There was a lack of rigor around the creation, development, and implementation of an alert, which led to sub-optimal alerts going to production without documentation or peer-review. Over time, some of these alerts gained a reputation of being low-quality, which led to fatigue, alerting apathy, or additional engineering time and resources.

To combat the issues and deficiencies previously noted, we developed an ADS Framework which is used for all alerting development. This is a natural language template which helps frame hypothesis generation, testing, and management of new ADS. 

The ADS Framework has the following sections, each which must be completed prior to production implementation:

* Goal
* Categorization
* Strategy Abstract
* Technical Context
* Blind Spots and Assumptions
* False Positives
* Validation
* Priority
* Response

Each section is required to successfully deploy a new ADS, and guarantees that any given alert will have sufficient documentation, will be validated for durability, and reviewed prior to production deployment. 

Each production or draft alert is based on the ADS framework is stored in a durable, version-controlled, and centralized location (e.g. Wiki, GitHub entry, etc.) 

## Repository Layout
This repository is organized as follows:
* [**ADS-Framework**](./ADS-Framework.md): The core ADS framework which is used internally at Palantir.
* [**ADS-Examples**](./ADS-Examples/): ADS examples which have been generated in accordance to this framework. These represent human-readable alerting strategies which may be deployed to detect malicious or anomalous activity.

### Using This Repository
**Note**: We recommend that you spin up a lab environment before deploying any of these configurations, scripts, or subscriptions to a production environment.

1. Download the repository and review the contents.
2. Run a ADS hack week and try converting or generating several new alerts.
3. Perform peer review of each new ADS and provide critical feedback. 
4. Start the process of converting legacy alerts into the ADS format.

## Contributing
Contributions, fixes, and improvements can be submitted directly against this project as a GitHub issue or pull request. 

## License
MIT License

Copyright (c) 2017 Palantir Technologies Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Further Reading and Acknowledgements

We would like to extend thanks to following for their contributions to the InfoSec community, or for assisting in the development of the ADS Framework:

* [MITRE ATT&CK Framework](https://attack.mitre.org/wiki/Main_Page)
* [Red Canary Atomic Red Team Testing Framework](https://github.com/redcanaryco/atomic-red-team)

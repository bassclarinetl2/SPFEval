#SPFEval: An SPF record parser and checker


This script will pull the SPF record for a given domain and will determine if a given
ip address is in that SPF record.

This script is intended for Python 2.7 and requires the [PythonDNS](www.dnspython.org) module.

##Usage

`python sfpeval.py domain ip address`

Example:

`python spfeval.py saratogafederated.org 23.30.39.89`

Returns:

`IP 23.30.39.89 is in the SPF record.`

#Copyright and Licence

*This is not an official Google Product.*

`Copyright 2015 Google Inc.  All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.`



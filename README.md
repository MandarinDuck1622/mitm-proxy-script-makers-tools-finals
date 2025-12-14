proxy1 command run:
mitmdump -s proxy1.py -p 8083 --mode upstream:http://127.0.0.1:8080 --ssl-insecure

proxy2 command run:
mitmdump -s proxy2.py -p 8084 --ssl-insecure

util command run:
python util.py

Description
Introduction
Malaysia's cyber security ecosystem has been transformed with the advent of the Cyber Security Act 2024, and this has created new demands for veteran professionals and easy-to-use security testing software. Current market products like Burp Suite Professional present significant barriers like exorbitant pricing, cluttered menus, and steep learning curves that are deterring usage by students and beginner penetration testers.
This project addresses these requirements by developing an open-source, education-dedicated MITM proxy tool for the Malaysian cybersecurity ecosystem. The tool is both a hands-on security testing platform and teaching resource, enabling cybersecurity capacity building in support of UN Sustainable Development Goal 9 (Industry, Innovation and Infrastructure).
The timing is particularly suitable with Malaysia's MyDigital vision and the increasing demand for cybersecurity professionals. Through the creation of a localized, user-friendly tool, this project is driving Malaysia's digitalization forward while fostering innovation in cybersecurity education.

Aim
To develop a comprehensive, user-friendly Man-in-the-Middle (MITM) proxy tool for bersecurity education and authorized penetration testing in Malaysia, while contributing to the nation's cybersecurity capacity building efforts in alignment with sustainable development goals.

Targeted Users
- Cybersecurity Students (University & College Level)
- Beginner Penetration Testers
- Cybersecurity Educators and Trainers
- Professional Penetration Testers
- Small and Medium Enterprises (SMEs) in Malaysia
- Cybersecurity Researchers

Objectives:
- Develop Core MITM Proxy Functionality
- Design Educational Framework
- Ensure Malaysian Regulatory Compliance
- Optimize User Experience and Accessibility
SDGsdg9
KeywordsForensic Analysis ToolsCybersecurityPhytonDigital Forensics CybersecurityCybersecurityEthical HackingEthical Hacking
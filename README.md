# Behaviour-Based-Firewall
In modern computer networks, and particularly in resource-constrained environments such as universities and small enterprises, network infrastructure security remains an acute issue due to the scarcity of proper tools for real-time monitoring and automated threat response. The project demonstrates a lightweight, modular solution utilizing Software Defined Networking (SDN) and unsupervised machine learning for real-time network anomaly detection and response. Based on the Ryu SDN controller and Mininet network simulation, the system employs an Isolation Forest algorithm for the detection of anomalous flow behavior and the triggering of automatic countermeasures such as flow blocking or rate limiting.
feel free to execute the code and any suggestions to future works will be truly appreciated
# Future works
It is in this project that several avenues leading to future research and development were opened. An
encouraging avenue of research was through real-time parsing and feature extraction of packets either
by having library functions like Scapy or PyShark be part of the detection pipeline. This would allow
the system to run raw PCAP packets in real time, eliminating the need to use pre-processed datasets and
streamline its capability to be able to perform in dynamic environments.
The discovery of self-healing mechanisms in networks was the other point of concern. This entailed the
need to come up with automation procedures that would enable the machine to restructure network
routes traffic redirection automatically upon periodical anomalies or malfunctions. This may increase
resilience and capability to perform in larger environments
Also, the system may be scaled for the purposes of distributed SDN systems, especially when the SDN
controllers provide a multi-controller framework like ONOS or Open Daylight. This growth would not
only make it fault tolerant but also enable the model to perform on the segmented network
environments, which are large. The system may ensure the profound responsiveness and that attack
surfaces are increased due to distribution of control and intelligence.
Such future functionality would be able to help in building the firewall system into scalable production
implementation of the firewall system that can handle the complex security problems in network
systems of the modern infrastructures.
Any recommendations to expand and grow the project will be trully appreciated.

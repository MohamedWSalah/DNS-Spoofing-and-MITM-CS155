# DNS-Spoofing-and-MITM-CS155
CS155 Part 4 DNS Spoofing and Man in the Middle Attack.

1-Sniffing the victim packets for a DNS packet, then reply to the victim with the attacker's fake DNS response and a fake website's IP address, which redirects the victim to our fake website.

2-Attacker will be in the middle between the packets coming and going from the victim to the real website, to be specific, the attacker will be the one redirects the packets from our fake website to the real one.

3-Sniff the packets for the needed info ( username and password ) once we recieve it, we redirect it to the real website to get the disered response.

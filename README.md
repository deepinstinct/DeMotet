# DeMotet
Unpacking and decryption tools for the Emotet malware by [Deep Instinct](https://www.deepinstinct.com/).<br />
The first tool is a static unpacker for the variants of the Emotet loader listed in *Loaders-SHA256.txt*. It can extract the encrypted payload from the resource without executing the malware.<br />
The Python scripts reveal the hidden strings and API calls the payload uses. The first one is a standalone script that can be used to extract this information from a large number of payloads. The second one is an IDA plugin. It adds this information as comments in the code.<br /><br />
![](images/IDA_plugin.png)
## References
- https://www.deepinstinct.com/blog/the-re-emergence-of-emotet
- https://cert.grnet.gr/en/blog/reverse-engineering-emotet/
- https://medium.com/threat-intel/emotet-dangerous-malware-keeps-on-evolving-ac84aadbb8de
- https://github.com/mauronz/binja-emotet

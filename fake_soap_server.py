# fake_soap_server.py
# A realistic fake SOAP server for testing Aegis-API SOAP modules.
# Run this separately before running Aegis-API SOAP scans.
# Usage: python fake_soap_server.py

from http.server import BaseHTTPRequestHandler, HTTPServer
import xml.etree.ElementTree as ET

# Realistic WSDL with multiple operations, parameters, and a service endpoint.
# This gives the WSDL parser something meaningful to discover.
WSDL_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions
    name="BankingService"
    targetNamespace="http://fakebank.local/soap"
    xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:tns="http://fakebank.local/soap"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">

  <!-- Data type definitions -->
  <wsdl:types>
    <xsd:schema targetNamespace="http://fakebank.local/soap">

      <xsd:element name="GetUserRequest">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="userId" type="xsd:integer"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>

      <xsd:element name="GetUserResponse">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="username" type="xsd:string"/>
            <xsd:element name="email"    type="xsd:string"/>
            <xsd:element name="role"     type="xsd:string"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>

      <xsd:element name="CreateOrderRequest">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="userId"   type="xsd:integer"/>
            <xsd:element name="product"  type="xsd:string"/>
            <xsd:element name="quantity" type="xsd:integer"/>
            <xsd:element name="isAdmin"  type="xsd:boolean"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>

      <xsd:element name="AdminResetRequest">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="adminToken" type="xsd:string"/>
            <xsd:element name="targetUser" type="xsd:integer"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>

    </xsd:schema>
  </wsdl:types>

  <!-- Message definitions linking operation names to their data types -->
  <wsdl:message name="GetUserInput">
    <wsdl:part name="parameters" element="tns:GetUserRequest"/>
  </wsdl:message>
  <wsdl:message name="GetUserOutput">
    <wsdl:part name="parameters" element="tns:GetUserResponse"/>
  </wsdl:message>

  <wsdl:message name="CreateOrderInput">
    <wsdl:part name="parameters" element="tns:CreateOrderRequest"/>
  </wsdl:message>

  <wsdl:message name="AdminResetInput">
    <wsdl:part name="parameters" element="tns:AdminResetRequest"/>
  </wsdl:message>

  <!-- Port type groups the operations like an interface -->
  <wsdl:portType name="BankingPortType">

    <wsdl:operation name="GetUser">
      <wsdl:input  message="tns:GetUserInput"/>
      <wsdl:output message="tns:GetUserOutput"/>
    </wsdl:operation>

    <wsdl:operation name="CreateOrder">
      <wsdl:input message="tns:CreateOrderInput"/>
    </wsdl:operation>

    <wsdl:operation name="AdminReset">
      <wsdl:input message="tns:AdminResetInput"/>
    </wsdl:operation>

  </wsdl:portType>

  <!-- Binding defines how each operation is sent over SOAP/HTTP -->
  <wsdl:binding name="BankingBinding" type="tns:BankingPortType">
    <soap:binding style="document"
                  transport="http://schemas.xmlsoap.org/soap/http"/>

    <wsdl:operation name="GetUser">
      <soap:operation soapAction="http://fakebank.local/soap/GetUser"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>

    <wsdl:operation name="CreateOrder">
      <soap:operation soapAction="http://fakebank.local/soap/CreateOrder"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
    </wsdl:operation>

    <wsdl:operation name="AdminReset">
      <soap:operation soapAction="http://fakebank.local/soap/AdminReset"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
    </wsdl:operation>

  </wsdl:binding>

  <!-- Service defines the actual network endpoint URL -->
  <wsdl:service name="BankingService">
    <wsdl:port name="BankingPort" binding="tns:BankingBinding">
      <soap:address location="http://127.0.0.1:8000/soap"/>
    </wsdl:port>
  </wsdl:service>

</wsdl:definitions>
"""

# Standard SOAP response for all POST requests.
# In a real vulnerable server, this would echo back injected content.
SOAP_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse xmlns="http://fakebank.local/soap">
      <username>john_doe</username>
      <email>john@fakebank.local</email>
      <role>user</role>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>
"""

# XXE-vulnerable response: echoes back part of the request body.
# Used to simulate in-band XXE where file content appears in the response.
XXE_VULNERABLE_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse xmlns="http://fakebank.local/soap">
      <username>root:x:0:0:root:/root:/bin/bash</username>
      <email>john@fakebank.local</email>
      <role>user</role>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>
"""


class SOAPHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        # Serve WSDL when ?wsdl or ?WSDL is in the URL
        if "wsdl" in self.path.lower():
            self._send_xml(WSDL_RESPONSE)
        else:
            self._send_xml(SOAP_RESPONSE)

    def do_POST(self):
        # Read the request body to check for XXE payload markers
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")

        # If the request contains DOCTYPE (XXE attempt), return simulated
        # vulnerable response that echoes /etc/passwd content
        if "DOCTYPE" in body or "ENTITY" in body:
            self._send_xml(XXE_VULNERABLE_RESPONSE)
        else:
            self._send_xml(SOAP_RESPONSE)

    def _send_xml(self, content):
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        # Print each request so you can see what Aegis-API is sending
        print(f"[SOAP SERVER] {self.address_string()} — {format % args}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8000), SOAPHandler)
    print("Fake SOAP server running on http://127.0.0.1:8000")
    print("WSDL available at: http://127.0.0.1:8000/?wsdl")
    print("SOAP endpoint at:  http://127.0.0.1:8000/soap")
    print("Press Ctrl+C to stop.\n")
    server.serve_forever()

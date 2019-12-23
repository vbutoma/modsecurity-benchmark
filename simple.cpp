#include <bits/stdc++.h>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules.h"

using modsecurity::Transaction;

char ip[] = "127.0.0.1";
char rules_file[] = "./configs/main.conf";
unsigned char requestBody[] = "{\"a\": \"&&||1//*-+\", \"b\": 123 }";

int main( ) {
    std::cout << "hello" << std::endl;
    #ifdef WITH_YAJL
    std::cout << "YAJL DEFINED !!!" << std::endl;
    #endif
    modsecurity::ModSecurity *modsec;
    modsecurity::Rules *rules;
    modsecurity::ModSecurityIntervention it;
    modsecurity::intervention::reset(&it);
    modsec = new modsecurity::ModSecurity();
    modsec->setConnectorInformation("ModSecurity-benchmark v0.0.1-alpha" \
            " (ModSecurity benchmark utility)");

    rules = new modsecurity::Rules();
    if (rules->loadFromUri(rules_file) < 0) {
        std::cout << "Problems loading the rules..." << std::endl;
        std::cout << rules->m_parserError.str() << std::endl;
        return -1;
    }

    Transaction *modsecTransaction = new Transaction(modsec, rules, NULL);
    modsecTransaction->processConnection(ip, 12345, "127.0.0.1", 80);
    if (modsecTransaction->intervention(&it)) {
        std::cout << "There is an intervention" << std::endl;           
    }

    modsecTransaction->addRequestHeader("User-Agent",
        "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) " \
        "Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)");
    modsecTransaction->addRequestHeader("Content-Type", "application/json");
    modsecTransaction->processRequestHeaders();
    if (modsecTransaction->intervention(&it)) {
        std::cout << "There is an intervention (Headers)" << std::endl;
    }
    modsecTransaction->appendRequestBody(requestBody, strlen((const char*)requestBody));
    modsecTransaction->processRequestBody();
    if (modsecTransaction->intervention(&it)) {
        std::cout << "There is an intervention (Body)" << std::endl;
    }
    
    delete modsecTransaction;
    delete rules;
    delete modsec;
    return 0;
}




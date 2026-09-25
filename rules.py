from models import SecurityRule

# Prompts that discuss an attack instead of attempting one. Checked before
# every rule below: the patterns are deliberately broad, and without this
# guard any security tutorial or exam question would score as an attack.
DISCUSSION = [
    r"(explain|describe|define|summarize|summarise|teach|clarify)\s+"
    r"(what|why|how|the\s+term)",

    r"what\s+(is|are|does|do)\s+.*(mean|means|meaning)",

    r"how\s+(can|do|does|should|would|might)\s+"
    r"(i|we|you|one|a\s+|an\s+)?\w*\s*"
    r"(prevent|defend|protect|mitigate|stop|detect|block|guard|harden|test)",

    r"why\s+.*is\s+(dangerous|bad|harmful|risky|unsafe|a\s+problem)",

    r"write\s+(a|an)\s+\w+\s+(about|on)\s+",

    r"(what|which)\s+is\s+\w+\s+mode\s+(on|in|for)\s+",
]

rules = [
    SecurityRule(
        name="instruction_override",
        patterns=[
            r"ignore\s+(all\s+|any\s+|your\s+|the\s+)?"
            r"(previous|prior|earlier|above|preceding)\s+"
            r"(instructions?|directives?|rules?|prompts?|commands?|guidelines?)",

            r"disregard\s+(all\s+|any\s+|the\s+|your\s+)?"
            r"(previous|prior|earlier|above|preceding)\s+"
            r"(instructions?|directives?|rules?|prompts?|commands?|guidelines?)",

            r"forget\s+(all\s+|any\s+|the\s+|your\s+)?"
            r"(previous|prior|earlier)\s+"
            r"(instructions?|directives?|rules?|prompts?)",

            r"forget\s+(everything|all)\s+"
            r"(you\s+(were\s+)?(told|given|taught|instructed)|"
            r"(that\s+)?came\s+before|before|above|previously)",

            r"(ignore|disregard)\s+everything\s+"
            r"(above|before|previously|you\s+(were\s+)?(told|given))",

            r"(discard|drop|skip|abandon|erase|wipe)\s+"
            r"(all\s+|the\s+|your\s+)?(previous|prior|earlier)\s+"
            r"(instructions?|rules?|directives?|prompts?)",

            r"(discard|drop|skip|abandon|erase|wipe)\s+"
            r"(all\s+|the\s+|your\s+)?"
            r"(previous|prior|earlier|original|initial)\s+"
            r"(instructions?|rules?|directives?|directions?|prompts?)",

            r"override\s+(all\s+|the\s+|your\s+)?"
            r"(previous|prior|earlier|system)\s+"
            r"(instructions?|rules?|directives?|prompts?)",

            r"(the\s+)?(previous|prior|earlier|above|former|original)\s+"
            r"(rules?|instructions?|directives?|guidelines?|prompts?)\s+"
            r"("
            r"no\s+longer\s+apply|"
            r"do\s+not\s+apply|"
            r"don't\s+apply|"
            r"are\s+(now\s+)?(void|invalid|cancelled|canceled|obsolete|irrelevant)|"
            r"should\s+be\s+considered\s+"
            r"(void|invalid|cancelled|canceled|obsolete|irrelevant)"
            r")",

            r"(stop|cease)\s+following\s+(all\s+|the\s+|your\s+)?"
            r"(previous|prior|earlier)?\s*"
            r"(instructions?|rules?|directives?|guidelines?)",

            r"(do\s+not|don't)\s+follow\s+(the\s+|your\s+|any\s+)?"
            r"(previous|prior|earlier|above)?\s*"
            r"(instructions?|rules?|directives?|guidelines?)",

            r"(new|updated|revised)\s+instructions?\s+"
            r"(supersede|replace|override)",

            r"your\s+(previous|prior|earlier|original|initial)\s+"
            r"(instructions?|rules?)\s+(are|were)\s+(wrong|fake|a\s+test)",
            r"(put|set|lay)\s+aside\s+"
            r"(all\s+|any\s+|the\s+|your\s+)?"
            r"(previous\s+|prior\s+|earlier\s+|initial\s+|original\s+)?"
            r"(instructions?|directions?|guidance|rules?|guidelines?)",

            r"(everything|all)\s+you\s+were\s+"
            r"(briefed|told|instructed)\s+"
            r"(on\s+)?(before|earlier|previously).*"
            r"(set|put)\s+aside",

            r"(guidance|instructions?|directions?|rules?|guidelines?)\s+"
            r"(you\s+)?(received|were\s+given)?\s*"
            r"(earlier|before|previously).*"
            r"(no\s+longer\s+(valid|applies?)|invalid|cancelled|canceled|void)",

            r"(rules?|instructions?|directions?|guidance|guidelines?)\s+"
            r"(from\s+)?(earlier|before|previously)\s+"
            r"(are\s+)?(cancelled|canceled|invalid|void|obsolete)",

            r"(let\s+go\s+of|discard|drop|abandon)\s+"
            r"(whatever\s+|all\s+|any\s+|the\s+|your\s+)?"
            r"(rules?|instructions?|directions?|guidance|guidelines?)",

            r"(stop|cease)\s+(obeying|following)\s+"
            r"(the\s+|your\s+)?"
            r"(rules?|instructions?|directions?|guidance|guidelines?)",

            r"(ignore|disregard|override|bypass)\s+"
            r"(the\s+)?"
            r"(instruction\s+)?hierarchy"
            r".{0,80}"
            r"(follow|obey|use)\s+"
            r"(my|this)\s+"
            r"(commands?|instructions?|directions?)",

            r"(ignore|disregard|forget|discard)\s+"
            r"(all\s+|any\s+|the\s+|your\s+)?"
            r"(instructions?|rules?|directives?|guidance|guidelines?)\s+"
            r"(above|before|previously)"
            r"(\s+(this\s+)?(message|point))?",

            r"(forget|ignore|discard|drop)\s+"
            r"(all\s+|any\s+|the\s+|your\s+)?"
            r"(constraints?|instructions?|rules?|guidelines?|directives?)\s+"
            r"(you\s+)?(were\s+)?"
            r"(given|provided|assigned|set)\s+"
            r"(at\s+|during\s+)?"
            r"(startup|initialization|initialisation|the\s+start)",
        ],
        score=40,
        severity="High",
        description="Attempts to override or ignore previous LLM instructions.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="system_prompt_extraction",
        patterns=[
            r"(show|reveal|print|display|give|tell|share|output|repeat|echo|"
            r"expose|disclose|dump|paste|send|leak)\s+"
            r"(me\s+|us\s+)?(your\s+|the\s+|its\s+)?"
            r"(exact\s+|full\s+|complete\s+|entire\s+|verbatim\s+|"
            r"original\s+|initial\s+)*"
            r"system\s+(prompt|message|instructions?)",

            r"what\s+(is|are|was|were)\s+(your|the)\s+"
            r"(exact\s+|full\s+|original\s+|initial\s+)*"
            r"system\s+(prompt|message|instructions?)",

            r"(repeat|print|output|echo|write|show)\s+"
            r"(everything|all\s+(the\s+)?text|the\s+text|the\s+words)\s+"
            r"((that\s+)?came\s+before|above|before\s+this|preceding|"
            r"prior\s+to\s+this)",

            r"(what|which)\s+(prompt|instructions?)\s+(were\s+you|are\s+you)\s+"
            r"(given|started\s+with|initialized\s+with)",

            r"(copy|reproduce|recite|quote)\s+(your\s+|the\s+)?"
            r"system\s+(prompt|message|instructions?)",

            # "your" is required: "print the first message in the mailbox"
            # is an ordinary request, not an extraction attempt.
            r"(print|output|show|repeat|give)\s+(me\s+)?your\s+"
            r"(initial|original|first|very\s+first)\s+"
            r"(prompt|message|instructions?)",

            r"(begin|start)\s+your\s+(reply|response|answer)\s+with\s+"
            r"(your\s+)?(system\s+)?(prompt|instructions?)",
            r"(i'?d\s+like\s+to\s+see|show\s+me|give\s+me|display)\s+"
            r"(the\s+)?(text|content|message|prompt|instructions?)\s+"
            r"(that\s+was\s+)?(placed|written|shown|provided)\s+"
            r"(above|before)"
            r"(\s+(my\s+message|this\s+message|me))?",

            r"(recite|repeat|reproduce|quote|output|print)\s+"
            r"(the\s+)?(words|text|message|prompt|instructions?)\s+"
            r"you\s+were\s+"
            r"(initialized|initialised|started|configured|set\s+up)\s+with",

            r"(give|show|send|provide)\s+me\s+"
            r"(a\s+)?copy\s+of\s+"
            r"(the\s+)?(message|prompt|instructions?)\s+"
            r"that\s+(set\s+you\s+up|initialized\s+you|configured\s+you|started\s+you)",
            r"(system\s+prompts?|system\s+instructions?).{0,120}"
            r"(print|output|show|reveal|repeat)\s+yours"
            r"(\s+verbatim)?",

            r"(show|reveal|give|print|output)\s+"
            r"(me\s+)?(the\s+|your\s+)?"
            r"(initial|original|first)\s+"
            r"(message|prompt|instructions?)\s+"
            r"that\s+"
            r"(set|defined|established|configured)\s+"
            r"(your\s+)?"
            r"(rules?|behavior|behaviour|instructions?)",
        ],

        context_patterns=[
            r"(protect|hide|secure|conceal).{0,50}"
            r"(prompts?|instructions?).{0,120}"
            r"(output|show|reveal|print|repeat)\s+yours",

            r"(system\s+prompts?|system\s+instructions?).{0,120}"
            r"(print|output|show|reveal|repeat)\s+yours"
            r"(\s+verbatim)?",
        ],

        score=30,
        severity="Medium",
        description="Attempts to extract the hidden system prompt.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="developer_prompt_extraction",
        patterns=[
            r"(show|reveal|print|display|give|tell|share|output|repeat|echo|"
            r"expose|disclose|dump|send|leak)\s+"
            r"(me\s+|us\s+)?(your\s+|the\s+)?"
            r"developer\s+(prompt|instructions?|messages?|notes?)",

            r"what\s+(is|are)\s+(your|the)\s+"
            r"developer\s+(prompt|instructions?|messages?)",

            r"(show|reveal|print|display|give|tell)\s+(me\s+)?(your\s+|the\s+)?"
            r"(operator|owner|creator|engineer)\s+"
            r"(prompt|instructions?|messages?)",
            r"(your\s+)?"
            r"(creators?|developers?|operators?|owners?)['’]?\s*"
            r"(notes?|instructions?|messages?|directions?).{0,40}"
            r"(show|reveal|give|share|display|output)\s+"
            r"(them|it)(\s+to\s+me)?",
            r"developer\s+(instructions?|prompts?|messages?).{0,120}"
            r"(show|reveal|print|output|give)\s+"
            r"(me\s+)?yours"
        ],

        context_patterns=[
            r"developer\s+"
            r"(instructions?|prompts?|messages?).{0,120}"
            r"(show|reveal|print|output|give)\s+"
            r"(me\s+)?yours",
        ],
        score=30,
        severity="Medium",
        description="Attempts to reveal developer-level instructions.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="sensitive_instruction_extraction",
        patterns=[
            r"(show|reveal|print|display|give|tell|share|output|repeat|echo|"
            r"expose|disclose|dump|send|leak|uncover|unveil)\s+"
            r"(me\s+|us\s+)?(the\s+|your\s+)?"
            r"(internal|hidden|secret|confidential|private|underlying|"
            r"concealed|sensitive|undisclosed)\s+"
            r"(instructions?|prompts?|messages?|rules?|directives?|"
            r"guidelines?|configuration|config|settings?)",

            r"(expose|reveal|show|print|display|disclose|leak|dump)\s+"
            r"(all\s+|the\s+|your\s+)?"
            r"(instructions?|prompts?|rules?|directives?|messages?)\s+"
            r"(hidden|concealed|withheld|kept\s+secret)\s+"
            r"from\s+(the\s+)?(users?|me|public)",

            r"what\s+(instructions?|rules?|directives?|prompts?)\s+"
            r"(are|were)\s+you\s+"
            r"(given|told|programmed\s+with|trained\s+with)",

            r"(is|are)\s+there\s+(any\s+)?"
            r"(hidden|secret|internal|confidential)\s+"
            r"(instructions?|rules?|prompts?)",

            r"(tell|show)\s+me\s+(what|everything)\s+you\s+(were\s+)?"
            r"(told|instructed)\s+"
            r"(not\s+to\s+(say|reveal|share)|to\s+hide)",
            r"what\s+(were|are)\s+you\s+"
            r"(told|instructed|asked)\s+"
            r"not\s+to\s+"
            r"(reveal|share|say|disclose|show)",


            r"(share|reveal|show|give|disclose|output)\s+"
            r"(me\s+)?(the\s+|your\s+)?"
            r"(confidential|hidden|internal|secret|private)\s+"
            r"(guidance|instructions?|rules?|directives?|policies?)"
            r"(\s+you\s+(operate|work|function)\s+under)?",


            r"(reveal|show|share|disclose|output)\s+"
            r"(anything|everything)\s+"
            r"you\s+were\s+(told|instructed)\s+"
            r"to\s+(keep|hide|withhold)\s+"
            r"from\s+(users?|me|the\s+public)",
            
            r"(hidden|secret|private|internal)\s+"
            r"(prompts?|instructions?|directives?).{0,120}"
            r"(reveal|show|print|output|give)\s+"
            r"(me\s+)?(the\s+)?one\s+"
            r"you\s+were\s+given"
        ],
        context_patterns=[
            r"(hidden|secret|private|internal)\s+"
            r"(prompts?|instructions?|directives?).{0,120}"
            r"(reveal|show|print|output|give)\s+"
            r"(me\s+)?(the\s+)?one\s+"
            r"you\s+were\s+given",
        ],
        score=35,
        severity="High",
        description="Attempts to reveal hidden or internal model instructions.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="role_manipulation",
        patterns=[
            r"(act|pretend|behave|respond|reply|talk|speak|operate|function|"
            r"roleplay|role-play)\s+(as|like)\s+"
            r"(if\s+you\s+(are|were)\s+)?(an?\s+|the\s+)?"
            r"(admin(istrator)?|developer|system|superuser|root|god|hacker)",

            r"(act|pretend|behave|respond|reply|talk|speak|operate|function|"
            r"roleplay|role-play)\s+(as|like)\s+"
            r"(if\s+you\s+(are|were)\s+)?(an?\s+|the\s+)?"
            r"(unrestricted|unfiltered|uncensored|unlimited|jailbroken|evil)\s*"
            r"(ai|assistant|model|chatbot|version)?",

            r"you\s+are\s+(now\s+)?(an?\s+)?"
            r"(admin(istrator)?|developer|superuser|root|dan)\b",

            r"you\s+are\s+(now\s+)?(an?\s+)?"
            r"(unrestricted|unfiltered|uncensored|jailbroken|evil)\s*"
            r"(ai|assistant|model|chatbot)?",

            r"assume\s+the\s+(role|identity|persona|character)\s+of",

            r"from\s+now\s+on,?\s+you\s+"
            r"(are|will\s+be|must\s+act|shall|no\s+longer)",

            r"you\s+(have|are\s+under)\s+no\s+"
            r"(restrictions?|limits?|limitations?|rules?|filters?|"
            r"guidelines?|constraints?)",

            r"(forget|drop)\s+(that\s+)?you\s+are\s+(an?\s+)?"
            r"(ai|assistant|language\s+model|chatbot)",

            r"simulate\s+(an?\s+)?"
            r"(unrestricted|unfiltered|uncensored|developer|admin)",
            r"(act|operate|function)\s+"
            r"in\s+the\s+capacity\s+of\s+"
            r"(an?\s+)?"
            r"(root|admin(istrator)?|developer|superuser|system)",
            r"(act|behave|operate|respond|speak)\s+"
            r"(as\s+though|as\s+if|like)\s+"
            r"(an?\s+)?(version\s+of\s+yourself\s+)?"
            r"(without|with\s+no)\s+"
            r"(any\s+|the\s+|your\s+)?"
            r"(guardrails?|restrictions?|filters?|limits?|limitations?|"
            r"content\s+policy|policies)",
            r"(act|operate|function|speak|respond|behave)\s+"
            r"(as\s+though|as\s+if)\s+"
            r"you\s+"
            r"("
            r"(were|are)\s+(an?\s+)?"
            r"(admin(istrator)?|root|superuser)"
            r"(\s+with\s+(full|unlimited)\s+privileges?)?"
            r"|"
            r"had\s+(admin(istrator)?|root|superuser)\s+privileges?"
            r")",
            r"(act|behave|operate|respond|speak)\s+"
            r"like\s+(a\s+)?version\s+of\s+yourself\s+"
            r"that\s+(has|had)\s+no\s+"
            r"(guardrails?|restrictions?|filters?|limits?|limitations?)"
        ],
        context_patterns=[
            r"(unfiltered|unrestricted|uncensored)\s+"
            r"(model|ai|assistant|chatbot).{0,120}"
            r"(behave|act|respond|operate)\s+like\s+one"
            
        ],
        score=25,
        severity="Medium",
        description="Attempts to manipulate the model into adopting an unauthorized role.",
        exclude=DISCUSSION,
    ),

    SecurityRule(
        name="jailbreak_attempt",
        patterns=[
            r"(enable|activate|enter|turn\s+on|switch\s+(in)?to|go\s+into|"
            r"start|engage)\s+(an?\s+|the\s+)?"
            r"(developer|jailbreak|dan|god|debug|admin|unrestricted|"
            r"unfiltered|uncensored|freedom|evil|sudo)\s+mode",

            # A safety qualifier is required here, so benign sysadmin requests
            # like "remove all restrictions on my disk quota" do not match.
            r"(disable|bypass|circumvent|turn\s+off|remove|lift|override|"
            r"evade|get\s+around|work\s+around|ignore|drop|relax)\s+"
            r"(all\s+|any\s+|every\s+|the\s+|your\s+)*"
            r"(safety|security|content|ethical|moral|ai)\s+"
            r"(rules?|restrictions?|filters?|guidelines?|guardrails?|"
            r"policy|policies|constraints?|limitations?|protections?|"
            r"safeguards?|censorship)",

            # ...or the target is explicitly the model's own guardrails.
            r"(disable|bypass|circumvent|turn\s+off|remove|lift|override|"
            r"evade|get\s+around|work\s+around|ignore)\s+"
            r"(all\s+|any\s+)?your\s+"
            r"(own\s+|built[-\s]?in\s+)?"
            r"(safety\s+|security\s+|content\s+|ethical\s+)?"
            r"(rules?|restrictions?|filters?|guidelines?|guardrails?|"
            r"policy|policies|constraints?|limitations?|protections?|"
            r"safeguards?)",

            r"(answer|respond|reply|speak|talk)\s+(without|with\s+no)\s+"
            r"(any\s+)?(restrictions?|filters?|limitations?|censorship|"
            r"guardrails?|rules?|limits?)",

            r"(without|with\s+no)\s+(any\s+)?"
            r"(safety|content|ethical|moral)\s+"
            r"(restrictions?|filters?|limitations?|guidelines?|guardrails?)",

            r"do\s+anything\s+now",

            r"jailbreak\s+(mode|you|yourself|the\s+(model|ai|assistant))",

            r"pretend\s+(that\s+)?(your|the)\s+"
            r"(safety|content|security)\s+(rules?|filters?|guidelines?)\s+"
            r"(do\s+not|don't)\s+exist",

            r"there\s+are\s+no\s+"
            r"(rules?|restrictions?|limits?|filters?|guidelines?)\s+"
            r"(here|anymore|now)",
            r"(speak|respond|reply|operate|behave)\s+"
            r"(as\s+if|as\s+though)\s+"
            r"(there\s+(was|were)\s+)?"
            r"no\s+"
            r"(content\s+polic(y|ies)|guardrails?|restrictions?|"
            r"filters?|limitations?|rules?)",
            r"(respond|reply|speak|behave|operate)\s+"
            r"(as\s+if|as\s+though)\s+"
            r"(your\s+|the\s+)?"
            r"(restrictions?|guardrails?|filters?|limitations?|rules?)\s+"
            r"(had\s+been|were|are)\s+"
            r"(lifted|removed|disabled|dropped|turned\s+off)",
            r"pretend\s+(that\s+)?"
            r"(the\s+|your\s+)?"
            r"(safety|security|content)\s+"
            r"(layer|filter|guardrails?|system)\s+"
            r"(was|were)\s+never\s+"
            r"(installed|enabled|added|configured)",r"(enter|switch\s+into|step\s+into|activate)\s+"
            r"(a\s+)?mode\s+"
            r"(where|in\s+which)\s+"
            r"(nothing|anything)\s+"
            r"(is\s+)?(off\s+limits|allowed|permitted)",r"(operate|respond|act|function|behave)\s+"
            r"(without|with\s+no)\s+"
            r"(the\s+usual\s+|any\s+)?"
            r"(ethical|safety|security|content|moral)\s+"
            r"(limitations?|restrictions?|constraints?|rules?|guidelines?)",
            r"(switch|enter|step)\s+"
            r"(into\s+)?(an?\s+)?mode\s+where\s+"
            r"(your\s+)?"
            r"(guardrails?|restrictions?|filters?|rules?)\s+"
            r"(no\s+longer\s+apply|do\s+not\s+apply|don't\s+apply)",
            r"(operate|respond|act|function|behave)\s+"
            r"(without|with\s+no)\s+"
            r"(any\s+of\s+)?"
            r"(your\s+)?"
            r"(usual\s+)?"
            r"(ethical|safety|security|content|moral)\s+"
            r"(limitations?|restrictions?|constraints?|rules?|guidelines?|guardrails?)"
        ],

        context_patterns=[
            r"(safety\s+filters?|guardrails?|restrictions?|limitations?).{0,120}"
            r"(answer|respond|reply|behave|operate)\s+"
            r"as\s+if\s+none\s+of\s+"
            r"(them|those|these)\s+"
            r"(existed|exist)",

            r"(guardrails?|restrictions?|filters?|limitations?).{0,120}"
            r"(continue|respond|answer|operate)\s+without\s+"
            r"(those|these|the)\s+"
            r"(guardrails?|restrictions?|filters?|limitations?)",

            r"(guardrails?|safety\s+filters?|restrictions?|limitations?).{0,120}"
            r"(disable|remove|bypass|turn\s+off)\s+"
            r"(them|those|these)"
        ],

        score=40,
        severity="High",
        description="Attempts to bypass or disable the model's safety restrictions.",
        exclude=DISCUSSION,
    ),
]

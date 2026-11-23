# Annotation guide — author-reviewed gold labels

The researcher must create and verify the gold annotations. The baseline output or an LLM answer is not gold.

For each example: (1) read the whole email, (2) mark every in-scope substring, (3) label it URL, URGENCY, or CREDENTIAL, (4) record exact [start,end) offsets and a brief rationale, (5) check each offset against the original text, and (6) mark REVIEWED only after manual verification.

**URL** includes explicit web URL strings, whether benign or suspicious. Do not label ordinary email addresses as URL cues.

**URGENCY** expresses actual recipient-directed pressure, threatened consequences, or a deadline used to demand action. Read in context; not every time reference is coercive.

**CREDENTIAL** is an actual request to share, enter, verify, or submit a password, passcode, verification code or other sign-in secret. Negated safety advice does not count.

### Essential hard negatives

- "Do not share your password" is not a credential request.
- "If someone says act now, report it" is a quotation, not an urgent demand.
- "Here's the public course page: https://course.example" contains a URL, not proof of a threat.
- "Meeting starts at 3 PM" is time information, not necessarily pressure.

Document disagreements and borderline labels. Preserve empty-label emails. Freeze gold before test scoring. Do not label examples after reading the final model predictions. Add provenance and AI-generated text disclosure.

**Present status:** gold annotation incomplete; no externally validated performance statistics claimed.

from modular_input import Field, FieldValidationException
from website_input_app.cssselector import CSSSelector

class SelectorField(Field):
    """
    Represents a selector for getting information from a web-page. The selector is converted to a
    LXML CSS selector instance.
    """

    @classmethod
    def parse_selector(cls, value, name):

        if value is not None and len(value.strip()) != 0:
            try:
                # Use the HTML translation so that selectors match accordingly ("DIV" should match "div")
                return CSSSelector(value, translator='html')
            except AssertionError as e:
                raise FieldValidationException("The value of '%s' for the '%s' parameter is not a valid selector: %s" % (str(value), name, str(e)))

    def to_python(self, value, session_key=None):
        Field.to_python(self, value, session_key)

        return SelectorField.parse_selector(value, self.name)

    def to_string(self, value):
        return value.css

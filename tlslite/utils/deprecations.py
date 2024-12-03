"""Methods for deprecating old names for arguments or attributes."""
import warnings
import inspect
from functools import wraps

def deprecated_class_name(old_name, warn="Class name '{old_name}' is deprecated, please use '{new_name}'"):
    """
    Class decorator to deprecate a use of class.

    :param str old_name: the deprecated name that will be registered, but
       will raise warnings if used.

    :param str warn: DeprecationWarning format string for informing the
       user what is the current class name, uses 'old_name' for the deprecated
       keyword name and the 'new_name' for the current one.
       Example: "Old name: {old_nam}, use '{new_name}' instead".
    """
    def decorator(cls):
        new_name = cls.__name__
        setattr(sys.modules[cls.__module__], old_name, cls)
        warnings.warn(warn.format(old_name=old_name, new_name=new_name), DeprecationWarning, stacklevel=2)
        return cls
    return decorator

def deprecated_params(names, warn="Param name '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to translate obsolete names and warn about their use.

    :param dict names: dictionary with pairs of new_name: old_name
        that will be used for translating obsolete param names to new names

    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for new_name, old_name in names.items():
                if old_name in kwargs:
                    warnings.warn(warn.format(old_name=old_name, new_name=new_name), DeprecationWarning, stacklevel=2)
                    kwargs[new_name] = kwargs.pop(old_name)
            return func(*args, **kwargs)
        return wrapper
    return decorator

def deprecated_instance_attrs(names, warn="Attribute '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to deprecate class instance attributes.

    Translates all names in `names` to use new names and emits warnings
    if the translation was necessary. Does apply only to instance variables
    and attributes (won't modify behaviour of class variables, static methods,
    etc.

    :param dict names: dictionary with paris of new_name: old_name that will
        be used to translate the calls
    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    def decorator(cls):
        class Wrapper(cls):
            def __getattr__(self, name):
                for new_name, old_name in names.items():
                    if name == old_name:
                        warnings.warn(warn.format(old_name=old_name, new_name=new_name), DeprecationWarning, stacklevel=2)
                        return getattr(self, new_name)
                return super().__getattr__(name)

            def __setattr__(self, name, value):
                for new_name, old_name in names.items():
                    if name == old_name:
                        warnings.warn(warn.format(old_name=old_name, new_name=new_name), DeprecationWarning, stacklevel=2)
                        return super().__setattr__(new_name, value)
                return super().__setattr__(name, value)

        return Wrapper
    return decorator

def deprecated_attrs(names, warn="Attribute '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to deprecate all specified attributes in class.

    Translates all names in `names` to use new names and emits warnings
    if the translation was necessary.

    Note: uses metaclass magic so is incompatible with other metaclass uses

    :param dict names: dictionary with paris of new_name: old_name that will
        be used to translate the calls
    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    class DeprecatedAttrsMeta(type):
        def __new__(cls, name, bases, attrs):
            for new_name, old_name in names.items():
                if old_name in attrs:
                    attrs[new_name] = attrs[old_name]
                    del attrs[old_name]

                def make_property(new_name, old_name):
                    def getter(self):
                        warnings.warn(warn.format(old_name=old_name, new_name=new_name), DeprecationWarning, stacklevel=2)
                        return getattr(self, new_name)

                    def setter(self, value):
                        warnings.warn(warn.format(old_name=old_name, new_name=new_name), DeprecationWarning, stacklevel=2)
                        setattr(self, new_name, value)

                    return property(getter, setter)

                attrs[old_name] = make_property(new_name, old_name)

            return super().__new__(cls, name, bases, attrs)

    def decorator(cls):
        return DeprecatedAttrsMeta(cls.__name__, cls.__bases__, dict(cls.__dict__))

    return decorator

def deprecated_method(message):
    """Decorator for deprecating methods.

    :param str message: The message you want to display.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            warnings.warn(f"{func.__name__} is deprecated. {message}", DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)
        return wrapper
    return decorator

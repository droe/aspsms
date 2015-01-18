TARGET=		aspsms-0.99.gem
GEM=		gem
GEMFLAGS=	

all: build

build: $(TARGET)

$(TARGET): aspsms.gemspec README LICENSE $(wildcard bin/* lib/*)
	$(GEM) $(GEMFLAGS) build $<

publish: $(TARGET)
	$(GEM) $(GEMFLAGS) push $<

clean:
	rm -f $(TARGET)

.PHONY: all build publish clean

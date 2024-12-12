CC = clang

CFLAGS = -O2 -static

SRCS = src/pw_gen.c src/hmac/sha2.c src/hmac/hmac_sha2.c

OBJS = $(addprefix output/,$(SRCS:.c=.o))

TARGET = output/pw_gen

all: $(TARGET)

$(shell mkdir -p output)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

output/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf output

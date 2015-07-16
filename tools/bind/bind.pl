#!/usr/bin/env perl
use strict;
use warnings;

use FindBin qw'$Bin';
use lib "$FindBin::Bin";
use lib "$FindBin::Bin/perl_lib";
BEGIN { $ENV{PERL_JSON_BACKEND} = 0 }
use JSON -support_by_pp;
use Data::Dumper;

open F,"<api.json" or die "failed to read api.json\n";
my $api;
{
    local $/;
    $api = <F>;
}
close F;

my $json = JSON->new;
$json->relaxed([1]);
$json->allow_singlequote([1]);
$json->allow_barekey([1]);

$api = $json->decode($api);
#print Dumper($api)."\n";
print "/* WARNING: autogenerated file */\n";
print "#include \"duktape.h\"\n";
print "#include \"../../deadbeef.h\"\n\n";
print "extern DB_functions_t *deadbeef;\n\n";

# int constants
print "void bind_int_constants (duk_context *ctx) {\n";
print "    duk_push_global_object(ctx);\n";
my $int_constants = $api->{int_constants};
foreach my $c (keys %$int_constants) {
    print "    duk_push_int(ctx, $int_constants->{$c});\n";
    print "    duk_put_prop_string(ctx, -2, \"$c\");\n";
}
print "    duk_pop(ctx);\n";
print "}\n\n";

my $functions = $api->{functions};

# function impls
foreach my $c (keys %$functions) {
    my $f = $functions->{$c};
    if ($f->{args} eq 'void' && $f->{ret} eq 'int') {
        print "int js_impl_$f->{name} (duk_context *ctx) {\n";
        print "    int val = deadbeef->$c ();\n";
        print "    duk_push_number(ctx, val);\n";
        print "    return 1;\n";
        print "}\n\n";
    }
    else {
        die "unsupported function type.\n" . Dumper($f) . "\n";
    }
}

# functions
print "void bind_functions (duk_context *ctx) {\n";
print "    duk_push_global_object(ctx);\n";
foreach my $c (keys %$functions) {
    my $f = $functions->{$c};
    print "    duk_push_c_function(ctx, js_impl_$f->{name}, 0);\n";
    print "    duk_put_prop_string(ctx, -2, \"$f->{name}\");\n";
}
print "    duk_pop(ctx);\n";
print "}\n\n";

# util
print "void duktape_bind_all (duk_context *ctx) {\n";
print "    bind_int_constants(ctx);\n";
print "    bind_functions(ctx);\n";
print "}\n\n";
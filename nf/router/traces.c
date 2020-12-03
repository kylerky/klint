#include <stdbool.h>
#include <stdint.h>

//@ #include "proof/ghost_map.gh"
//@ #include "bitops.gh"
//@ #include "nat.gh"
//@ #include "listutils.gh"

/*
State 140656413748336 has 27 constraints
    LpmAlloc ( )  -> <BV64 lpm_opaque_2_64>
    ---------------------------------
    HistoryNew(key_size=40, value_size=16, result=<BV64 lpm_table_opaque_3_64>)
    HistoryNewArray(key_size=64, value_size=24224, length=<BV64 0x1>, result=<BV64 packet_data_addr_opaque_7_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packet_datafracs_addr_opaque_8_64>)
    HistoryForall(obj=<BV64 packet_datafracs_addr_opaque_8_64>, pred=<Bool record_value_12_8 == 100>, pred_key=<BV64 record_key_11_64>, pred_value=<BV8 record_value_12_8>, result=<Bool packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100>)
    HistoryNewArray(key_size=64, value_size=336, length=<BV64 0x1>, result=<BV64 packet_addr_opaque_14_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packetfracs_addr_opaque_15_64>)
    HistoryForall(obj=<BV64 packetfracs_addr_opaque_15_64>, pred=<Bool record_value_19_8 == 100>, pred_key=<BV64 record_key_18_64>, pred_value=<BV8 record_value_19_8>, result=<Bool packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336>, <Bool BoolS(packet_addr_3_present_23_-1)>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
*/

/*@
	fixpoint bool forall_fix(list<bool> key, list<bool> value) {
		return int_of_bits(0, value) == 100;
	}
@*/

void not_ipv4_over_ethernet()
//@ requires true;
//@ ensures true;
{
    //@ list<pair<list<bool>, list<bool> > > lpm_table_opaque_3_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_data_addr_opaque_7_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_datafracs_addr_opaque_8_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_addr_opaque_14_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packetfracs_addr_opaque_15_64 = nil;

    int packet_datafracs_addr_2_test_key_9_64;
    int packet_datafracs_addr_2_test_value_10_8;
    //@ assume(ghostmap_forall(packet_datafracs_addr_opaque_8_64, forall_fix) == (packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100));

    int packetfracs_addr_4_test_key_16_64;
    int packetfracs_addr_4_test_value_17_8;
    //@ assume(ghostmap_forall(packetfracs_addr_opaque_15_64, forall_fix) == (packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100));

    bool packetfracs_addr_4_present_21_1;
    uint8_t packetfracs_addr_4_value_20_8;
    if (packetfracs_addr_4_present_21_1)
    {
        //@ assume (ghostmap_get(packetfracs_addr_opaque_15_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packetfracs_addr_4_value_20_8, N8))));
    }
    else
    {
        //@ assume (ghostmap_get(packetfracs_addr_opaque_15_64, snd(bits_of_int(0, N64))) == none);
    }

    bool packet_datafracs_addr_2_present_60_1;
    uint8_t packet_datafracs_addr_2_value_59_8;
    if (packet_datafracs_addr_2_present_60_1)
    {
        //@ assume (ghostmap_get(packet_datafracs_addr_opaque_8_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packet_datafracs_addr_2_value_59_8, N8))));
    }
    else
    {
        //@ assume (ghostmap_get(packet_datafracs_addr_opaque_8_64, snd(bits_of_int(0, N64))) == none);
    }

    bool packet_data_addr_1_present_62_1;
    int packet_data_addr_1_value_61_24224; // @TODO Actually a bitvector of length 24224. How do we store this ?
    if (packet_data_addr_1_present_62_1)
    {
        //@ assume (ghostmap_get(packet_data_addr_opaque_7_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packet_data_addr_1_value_61_24224, nat_of_int(24224)))));
    }
    else
    {
        //@ assume (ghostmap_get(packet_data_addr_opaque_7_64, snd(bits_of_int(0, N64))) == none);
    }

    //@ assert (true);
}

/*
State 140656413500464 has 30 constraints
    LpmAlloc ( )  -> <BV64 lpm_opaque_2_64>
    LpmLookupElem ( <BV64 lpm_opaque_2_64>, <BV64 0x0 .. packet_data_addr_1_value_61_24224[12383:12352]>, <BV64 0x7fffffffffeffca>, <BV64 0x7fffffffffeffcc>, <BV64 0x7fffffffffeffc9>)  -> <BV8 0>
    ---------------------------------
    HistoryNew(key_size=40, value_size=16, result=<BV64 lpm_table_opaque_3_64>)
    HistoryNewArray(key_size=64, value_size=24224, length=<BV64 0x1>, result=<BV64 packet_data_addr_opaque_7_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packet_datafracs_addr_opaque_8_64>)
    HistoryForall(obj=<BV64 packet_datafracs_addr_opaque_8_64>, pred=<Bool record_value_12_8 == 100>, pred_key=<BV64 record_key_11_64>, pred_value=<BV8 record_value_12_8>, result=<Bool packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100>)
    HistoryNewArray(key_size=64, value_size=336, length=<BV64 0x1>, result=<BV64 packet_addr_opaque_14_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packetfracs_addr_opaque_15_64>)
    HistoryForall(obj=<BV64 packetfracs_addr_opaque_15_64>, pred=<Bool record_value_19_8 == 100>, pred_key=<BV64 record_key_18_64>, pred_value=<BV8 record_value_19_8>, result=<Bool packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336>, <Bool BoolS(packet_addr_3_present_23_-1)>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryForall(obj=<BV64 lpm_table_opaque_3_64>, pred=<Bool record_key_72_40[7:0] < out_prefixlen_69_8 || LShR(record_key_72_40[39:8], (0#24 .. 32 - record_key_72_40[7:0])) != LShR(out_prefix_68_32, (0#24 .. 32 - out_prefixlen_69_8)) || record_key_72_40 == (out_prefix_68_32 .. out_prefixlen_69_8)>, pred_key=<BV40 record_key_72_40>, pred_value=<BV16 record_value_73_16>, result=<Bool 0x0 >= havoced_length_5_64 || lpm_table_0_test_key_70_40[7:0] < out_prefixlen_69_8 || LShR(lpm_table_0_test_key_70_40[39:8], (0#24 .. 32 - lpm_table_0_test_key_70_40[7:0])) != LShR(out_prefix_68_32, (0#24 .. 32 - out_prefixlen_69_8)) || lpm_table_0_test_key_70_40 == (out_prefix_68_32 .. out_prefixlen_69_8)>)
    HistoryGet(obj=<BV64 lpm_table_opaque_3_64>, key=<BV40 out_prefix_68_32 .. out_prefixlen_69_8>, result=(<BV16 lpm_table_0_value_74_16>, <Bool BoolS(lpm_table_0_present_75_-1)>))
*/

/*@
	fixpoint bool forall_lpm(int out_prefix, int out_prefixlen, list<bool> key, list<bool> value) {
        // shorter prefix || no_match || match
        return int_of_bits(0, take(8, key)) < out_prefixlen || int_of_bits(0, drop(40 - int_of_bits(0, take(8, key)), key)) == int_of_bits(0, drop(40 - out_prefixlen, snd(bits_of_int(out_prefix, N32)))) || int_of_bits(0, key) == ((out_prefix * pow_nat(2, N8)) + out_prefixlen);
    }
@*/

void lpm_lookup_fail()
//@ requires true;
//@ ensures true;
{
    //@ list<pair<list<bool>, list<bool> > > lpm_table_opaque_3_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_data_addr_opaque_7_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_datafracs_addr_opaque_8_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_addr_opaque_14_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packetfracs_addr_opaque_15_64 = nil;

    int packet_datafracs_addr_2_test_key_9_64;
    int packet_datafracs_addr_2_test_value_10_8;
    //@ assume(ghostmap_forall(packet_datafracs_addr_opaque_8_64, forall_fix) == (packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100));

    int packetfracs_addr_4_test_key_16_64;
    int packetfracs_addr_4_test_value_17_8;
    //@ assume(ghostmap_forall(packetfracs_addr_opaque_15_64, forall_fix) == (packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100));

    bool packetfracs_addr_4_present_21_1;
    uint8_t packetfracs_addr_4_value_20_8;
    if (packetfracs_addr_4_present_21_1)
    {
        //@ assume (ghostmap_get(packetfracs_addr_opaque_15_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packetfracs_addr_4_value_20_8, N8))));
    }
    else
    {
        //@ assume (ghostmap_get(packetfracs_addr_opaque_15_64, snd(bits_of_int(0, N64))) == none);
    }

    bool packet_datafracs_addr_2_present_60_1;
    uint8_t packet_datafracs_addr_2_value_59_8;
    if (packet_datafracs_addr_2_present_60_1)
    {
        //@ assume (ghostmap_get(packet_datafracs_addr_opaque_8_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packet_datafracs_addr_2_value_59_8, N8))));
    }
    else
    {
        //@ assume (ghostmap_get(packet_datafracs_addr_opaque_8_64, snd(bits_of_int(0, N64))) == none);
    }

    bool packet_data_addr_1_present_62_1;
    int packet_data_addr_1_value_61_24224; // @TODO Actually a bitvector of length 24224. How do we store this ?
    if (packet_data_addr_1_present_62_1)
    {
        //@ assume (ghostmap_get(packet_data_addr_opaque_7_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packet_data_addr_1_value_61_24224, nat_of_int(24224)))));
    }
    else
    {
        //@ assume (ghostmap_get(packet_data_addr_opaque_7_64, snd(bits_of_int(0, N64))) == none);
    }

    int out_prefix_68_32;
    int out_prefixlen_69_8;
    int havoced_length_5_64;
    int lpm_table_0_test_key_70_40;
    //@ list<bool> key = snd(bits_of_int(lpm_table_0_test_key_70_40, nat_of_int(40)));
    //@ bool shorter_prefix = int_of_bits(0, take(8, key)) < out_prefixlen_69_8;
    //@ bool no_match = int_of_bits(0, drop(40 - int_of_bits(0, take(8, key)), key)) == int_of_bits(0, drop(40 - out_prefixlen_69_8, snd(bits_of_int(out_prefix_68_32, N32))));
    //@ bool match = int_of_bits(0, key) == ((out_prefix_68_32 * pow_nat(2, N8)) + out_prefixlen_69_8);
    //@ assume(ghostmap_forall(lpm_table_opaque_3_64, (forall_lpm)(out_prefix_68_32, out_prefixlen_69_8)) == (0 >= havoced_length_5_64 || shorter_prefix || no_match || match));

    bool lpm_table_0_present_75_1;
    uint16_t lpm_table_0_value_74_16;
    if (lpm_table_0_present_75_1)
    {
        //@ assume (ghostmap_get(lpm_table_opaque_3_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(lpm_table_0_value_74_16, N16))));
    }
    else
    {
        //@ assume (ghostmap_get(lpm_table_opaque_3_64, snd(bits_of_int(0, N64))) == none);
    }

    //@ assert (true);
}

/*
State 140656413149744 has 30 constraints
    LpmAlloc ( )  -> <BV64 lpm_opaque_2_64>
    LpmLookupElem ( <BV64 lpm_opaque_2_64>, <BV64 0x0 .. packet_data_addr_1_value_61_24224[12383:12352]>, <BV64 0x7fffffffffeffca>, <BV64 0x7fffffffffeffcc>, <BV64 0x7fffffffffeffc9>)  -> <BV8 1>
    Transmit ( <BV64 packet_addr_opaque_14_64>, <BV64 0x0 .. out_value_67_16>, <BV64 0x5ea + packet_data_addr_opaque_7_64>, <BV64 0x5f8 + packet_data_addr_opaque_7_64>, <BV64 0x0>) 
    ---------------------------------
    HistoryNew(key_size=40, value_size=16, result=<BV64 lpm_table_opaque_3_64>)
    HistoryNewArray(key_size=64, value_size=24224, length=<BV64 0x1>, result=<BV64 packet_data_addr_opaque_7_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packet_datafracs_addr_opaque_8_64>)
    HistoryForall(obj=<BV64 packet_datafracs_addr_opaque_8_64>, pred=<Bool record_value_12_8 == 100>, pred_key=<BV64 record_key_11_64>, pred_value=<BV8 record_value_12_8>, result=<Bool packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100>)
    HistoryNewArray(key_size=64, value_size=336, length=<BV64 0x1>, result=<BV64 packet_addr_opaque_14_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packetfracs_addr_opaque_15_64>)
    HistoryForall(obj=<BV64 packetfracs_addr_opaque_15_64>, pred=<Bool record_value_19_8 == 100>, pred_key=<BV64 record_key_18_64>, pred_value=<BV8 record_value_19_8>, result=<Bool packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336>, <Bool BoolS(packet_addr_3_present_23_-1)>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryForall(obj=<BV64 lpm_table_opaque_3_64>, pred=<Bool record_key_72_40[7:0] < out_prefixlen_69_8 || LShR(record_key_72_40[39:8], (0#24 .. 32 - record_key_72_40[7:0])) != LShR(out_prefix_68_32, (0#24 .. 32 - out_prefixlen_69_8)) || record_key_72_40 == (out_prefix_68_32 .. out_prefixlen_69_8)>, pred_key=<BV40 record_key_72_40>, pred_value=<BV16 record_value_73_16>, result=<Bool 0x0 >= havoced_length_5_64 || lpm_table_0_test_key_70_40[7:0] < out_prefixlen_69_8 || LShR(lpm_table_0_test_key_70_40[39:8], (0#24 .. 32 - lpm_table_0_test_key_70_40[7:0])) != LShR(out_prefix_68_32, (0#24 .. 32 - out_prefixlen_69_8)) || lpm_table_0_test_key_70_40 == (out_prefix_68_32 .. out_prefixlen_69_8)>)
    HistoryGet(obj=<BV64 lpm_table_opaque_3_64>, key=<BV40 out_prefix_68_32 .. out_prefixlen_69_8>, result=(<BV16 lpm_table_0_value_74_16>, <Bool BoolS(lpm_table_0_present_75_-1)>))
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistorySet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, value=<BV8 0>)
*/

void lpm_lookup_success()
//@ requires true;
//@ ensures true;
{
    //@ list<pair<list<bool>, list<bool> > > lpm_table_opaque_3_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_data_addr_opaque_7_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_datafracs_addr_opaque_8_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packet_addr_opaque_14_64 = nil;
    //@ list<pair<list<bool>, list<bool> > > packetfracs_addr_opaque_15_64 = nil;

    int packet_datafracs_addr_2_test_key_9_64;
    int packet_datafracs_addr_2_test_value_10_8;
    //@ assume(ghostmap_forall(packet_datafracs_addr_opaque_8_64, forall_fix) == (packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100));

    int packetfracs_addr_4_test_key_16_64;
    int packetfracs_addr_4_test_value_17_8;
    //@ assume(ghostmap_forall(packetfracs_addr_opaque_15_64, forall_fix) == (packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100));

    bool packetfracs_addr_4_present_21_1;
    uint8_t packetfracs_addr_4_value_20_8;
    if (packetfracs_addr_4_present_21_1)
    {
        //@ assume (ghostmap_get(packetfracs_addr_opaque_15_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packetfracs_addr_4_value_20_8, N8))));
    }
    else
    {
        //@ assume (ghostmap_get(packetfracs_addr_opaque_15_64, snd(bits_of_int(0, N64))) == none);
    }

    bool packet_datafracs_addr_2_present_60_1;
    uint8_t packet_datafracs_addr_2_value_59_8;
    if (packet_datafracs_addr_2_present_60_1)
    {
        //@ assume (ghostmap_get(packet_datafracs_addr_opaque_8_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packet_datafracs_addr_2_value_59_8, N8))));
    }
    else
    {
        //@ assume (ghostmap_get(packet_datafracs_addr_opaque_8_64, snd(bits_of_int(0, N64))) == none);
    }

    bool packet_data_addr_1_present_62_1;
    int packet_data_addr_1_value_61_24224; // @TODO Actually a bitvector of length 24224. How do we store this ?
    if (packet_data_addr_1_present_62_1)
    {
        //@ assume (ghostmap_get(packet_data_addr_opaque_7_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(packet_data_addr_1_value_61_24224, nat_of_int(24224)))));
    }
    else
    {
        //@ assume (ghostmap_get(packet_data_addr_opaque_7_64, snd(bits_of_int(0, N64))) == none);
    }

    int out_prefix_68_32;
    int out_prefixlen_69_8;
    int havoced_length_5_64;
    int lpm_table_0_test_key_70_40;
    //@ list<bool> key = snd(bits_of_int(lpm_table_0_test_key_70_40, nat_of_int(40)));
    //@ bool shorter_prefix = int_of_bits(0, take(8, key)) < out_prefixlen_69_8;
    //@ bool no_match = int_of_bits(0, drop(40 - int_of_bits(0, take(8, key)), key)) == int_of_bits(0, drop(40 - out_prefixlen_69_8, snd(bits_of_int(out_prefix_68_32, N32))));
    //@ bool match = int_of_bits(0, key) == ((out_prefix_68_32 * pow_nat(2, N8)) + out_prefixlen_69_8);
    //@ assume(ghostmap_forall(lpm_table_opaque_3_64, (forall_lpm)(out_prefix_68_32, out_prefixlen_69_8)) == (0 >= havoced_length_5_64 || shorter_prefix || no_match || match));

    bool lpm_table_0_present_75_1;
    uint16_t lpm_table_0_value_74_16;
    if (lpm_table_0_present_75_1)
    {
        //@ assume (ghostmap_get(lpm_table_opaque_3_64, snd(bits_of_int(0, N64))) == some(snd(bits_of_int(lpm_table_0_value_74_16, N16))));
    }
    else
    {
        //@ assume (ghostmap_get(lpm_table_opaque_3_64, snd(bits_of_int(0, N64))) == none);
    }

    //@ ghostmap_set(packet_datafracs_addr_opaque_8_64, snd(bits_of_int(0, N64)), snd(bits_of_int(0, N8)));

    //@ assert (true);
}
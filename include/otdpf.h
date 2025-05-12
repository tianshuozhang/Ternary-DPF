#ifndef _OTDPF
#define _OTDPF
#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef __cplusplus
extern "C" {
#endif

#include "prf.h"

#ifdef __cplusplus
}

#endif
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

template <typename T>
double cot(T * ot, NetIO *io, int party, int64_t length) {
	block *b0 = new block[length], *r = new block[length];
	bool *b = new bool[length];
	block delta;
	PRG prg;
	prg.random_block(&delta, 1);
	prg.random_bool(b, length);

	io->sync();
	auto start = clock_start();
	if (party == ALICE) {
		ot->send_cot(b0, length);
		delta = ot->Delta;
	} else {
		ot->recv_cot(r, b, length);
	}
	io->flush();
	long long t = time_from(start);
	if (party == ALICE) {
		io->send_block(&delta, 1);
		io->send_block(b0, length);
	}
	else if (party == BOB) {
		io->recv_block(&delta, 1);
		io->recv_block(b0, length);
		
	}
	io->flush();
	delete[] b0;
	delete[] r;
	delete[] b;
	return t;
}

struct CorrectionWord {
    uint128_t cw0;
    uint128_t cw1;
    uint128_t cw2;
    uint8_t cb0;
    uint8_t cb1;
    uint8_t cb2;
    CorrectionWord operator^(const CorrectionWord& other) const {
        CorrectionWord res;
        res.cw0 =  this->cw0 ^ other.cw0;
        res.cw1 = this->cw1 ^ other.cw1;
        res.cw2 = this->cw2 ^ other.cw2;
        res.cb0 =  this->cb0 ^ other.cb0;
        res.cb1 = this->cb1 ^ other.cb1;
        res.cb2 = this->cb2 ^ other.cb2;
        return res;
    }
    // 重载输出运算符
    friend std::ostream& operator<<(std::ostream& os, const CorrectionWord& cw) {
        os << "CorrectionWord(\n  " << static_cast<int>(cw.cw0)<<"\t" <<static_cast<int>(cw.cb0)<< ",\n  " << 
        static_cast<int>(cw.cw1) <<"\t" <<static_cast<int>(cw.cb1)<< ",\n  " << 
        static_cast<int>(cw.cw2) <<"\t" <<static_cast<int>(cw.cb2)<< "\n)";
        return os;
    }
};

class EmpTernaryOt{
    public:
    NetIO* io;
    int party;
    EmpTernaryOt(NetIO* netio,int party_id) : io(netio),party(party_id){}

    EmpTernaryOt(NetIO* netio) : io(netio),party(100){}

    template <typename T>
    void sendCorrection(T*corrections,const uint128_t &length) {
        
        
        const uint32_t length1 = std::ceil(static_cast<double>(length) / sizeof(block));
        if(length%sizeof(block)!=0){
            throw std::runtime_error("错误: length 不是 block 大小的整数倍！");
        }
        
        block* b0 = new block[length1<<1]();
        block* b1 = new block[length1<<1]();
        
        memcpy(reinterpret_cast<char*>(b0) , reinterpret_cast<char*>(corrections), length);
        memcpy(reinterpret_cast<char*>(b1) , reinterpret_cast<char*>(corrections)+length, length);
        
        memcpy(reinterpret_cast<char*>(b0) + length, reinterpret_cast<char*>(corrections) + length*2, length);

        // 执行OT发送
        OTNEW<NetIO> ot(io);
        ot.send(b0, b1, length1);
        // std::cout<<"send over"<<std::endl;
        delete[] b0;
        delete[] b1;

    }
    template <typename T>
    void recvCorrection(T *corrections,const uint8_t & alpha , const uint128_t &length) {
        OTNEW<NetIO> ot(io);
        const uint32_t length1 = std::ceil(static_cast<double>(length) / sizeof(block));
        
        block* r = new block[length1];
        bool* b = new bool[length1<<1];
        int copy_size = length;
        int size = 0;
        for (uint8_t i = 0; i < length1 ;++i){
                b[i] = alpha%2;
                b[i+length1]=alpha/2;
        }
        
        
        // 执行OT接收
        ot.recv(r, b, length1);

       
       
        
        memcpy(corrections, r, length);
                
        
        // std::cout<<"recv over"<<std::endl;

        delete[] r;
        delete[] b;
    }
};

class DPFParty {
    public:
        
        DPFParty(PRFKeys* prf_keys, size_t domain_size, size_t index, 
                const std::vector<uint128_t>& msg_blocks, int party_id);
    
        void generate(NetIO* io);
        void simple_generate(NetIO *io=NULL,FerretCOT<NetIO> *ferretcot=NULL);
        void fulldomainevaluation(std::vector<uint128_t> &current_seeds_);
        size_t get_key_size();
        DPFParty& operator=(const DPFParty& other);
        DPFParty();

    private:
        PRFKeys* prf_keys_;
        size_t domain_size_;
        size_t index_;
        std::vector<uint128_t> msg_blocks_;
        const uint8_t party_id_;
        
        
        std::vector<CorrectionWord> all_corrections_; // 存储各层纠正字
        // uint128_t initial_seeds_;
        uint8_t control_bit;
        std::vector<uint128_t> initial_seeds_;              // [numPoints]
    
        void initialize_seeds();
        void process_levels(NetIO* io, std::vector<uint128_t>&current_seeds_,std::vector<uint8_t> &current_bits) ;
        void apply_corrections(std::vector<CorrectionWord> &corrections, std::vector<uint8_t>control_bits,std::vector<uint128_t> &current_seeds_,std::vector<uint8_t>&current_bits);
        void broadcast_corrections(NetIO *io,std::vector<CorrectionWord> &corrections);
        void exchange_prfkeys(NetIO *io);
        std::vector<CorrectionWord> compute_corrections(size_t level,EmpTernaryOt& ot,std::vector<uint128_t> &current_seeds_,std::vector<uint8_t> cb) ;
        std::string u128_to_binary(__uint128_t num) ;
        std::vector<uint8_t> expand_seeds(std::vector<uint128_t> &current_seeds_,std::vector<uint8_t> &current_bits);
        void apply_batch_corrections(
            std::vector<uint128_t>& new_seeds,          // 待校正的子节点集合
            std::vector<uint8_t>& new_bits,
            const std::vector<uint8_t>& parent_bits, // 父节点集合
            const size_t level       // 本层校正字
        );
        
    
        
    };
    


#endif
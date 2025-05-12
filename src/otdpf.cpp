#include <vector>
#include <memory>
#include <stdexcept>
#include <cstring>
#include"otdpf.h"

#ifdef __cplusplus
extern "C" {
#endif
#include"utils.h"
#ifdef __cplusplus

}
#endif





    
DPFParty::DPFParty(PRFKeys* prf_keys, size_t domain_size, size_t index, 
            const std::vector<uint128_t>& msg_blocks, int party_id)
        : prf_keys_(prf_keys), domain_size_(domain_size),
          index_(index), msg_blocks_(msg_blocks), party_id_(party_id) {};

void DPFParty::generate(NetIO* io) {
        
        std::vector<uint8_t> current_bits;
        initialize_seeds();
        std::vector<uint128_t> current_seeds_(initial_seeds_);
        
        for(size_t i = 0 ; i < msg_blocks_.size();++i) current_bits.push_back(control_bit);
        
        // std::cout<<"exchange keys\n";
        exchange_prfkeys(io);
        // std::cout<<"exchange keys over\n";
        process_levels(io,current_seeds_,current_bits);
        // std::cout<<"output\n";
    };
void DPFParty::simple_generate(NetIO *io,FerretCOT<NetIO> *ferretcot){
        initialize_seeds();
        
        int64_t len = sizeof(CorrectionWord)*msg_blocks_.size()/8;
        for(int i =0;i < domain_size_;++i){
             cot(ferretcot, io, party_id_, len);
        }
        all_corrections_.resize(domain_size_*msg_blocks_.size());
        // for (size_t level = 0; level < domain_size_; ++level) {
            //  cot(ferretcot, io, party_id_, sizeof(CorrectionWord)/8);
        // }
        
    };
    
void DPFParty::exchange_prfkeys(NetIO *io){
    if(party_id_==1){
        uint128_t receive[4];
        
        
        receive[0] = prf_keys_->key0;
        receive[1] = prf_keys_->key1;
        receive[2] = prf_keys_->key2;
        receive[3] = prf_keys_->key_ext;

        io->send_data(reinterpret_cast<char*>(receive),4*sizeof(uint128_t));
        io->flush();
    }
    else{
        uint128_t receive[4];
        
        io->recv_data(reinterpret_cast<char*>(receive),4*sizeof(uint128_t));
    
        uint8_t key0[16];
        uint8_t key1[16];
        uint8_t key2[16];
        uint8_t key_ext[16];


        memcpy(key0,receive,sizeof(uint128_t));
        memcpy(key1,receive+1,sizeof(uint128_t));
        memcpy(key2,receive+2,sizeof(uint128_t));
        memcpy(key_ext,receive+3,sizeof(uint128_t));


        EVP_CIPHER_CTX *prf_key0 = InitKey(key0);
        EVP_CIPHER_CTX *prf_key1 = InitKey(key1);
        EVP_CIPHER_CTX *prf_key2 = InitKey(key2);
        EVP_CIPHER_CTX *prf_key_ext = InitKey(key_ext);

        prf_keys_->prf_key0 = prf_key0;
        prf_keys_->prf_key1 = prf_key1;
        prf_keys_->prf_key2 = prf_key2;
        prf_keys_->prf_key_ext = prf_key_ext;
    }
}
    

void DPFParty::initialize_seeds() {

        initial_seeds_.resize(msg_blocks_.size());
        RAND_bytes(reinterpret_cast<uint8_t*>(initial_seeds_.data()), 16*msg_blocks_.size());
        

        control_bit = party_id_==1 ? 1 : 0 ;


        // initial_seeds_ = (initial_seeds_ & ~uint128_t(1)) | (control_bit & uint8_t(1));
        
    };

void DPFParty::process_levels(NetIO* io,std::vector<uint128_t> &current_seeds_,std::vector<uint8_t> &current_bits) {
        EmpTernaryOt ot(io,party_id_);
        // std::cout<<"begin process levels\n";
        for (size_t level = 0; level < domain_size_; ++level) {
            // std::cout<<"level:\t"<<static_cast<int>(level)<<"\n";
            auto control_bits = expand_seeds(current_seeds_,current_bits);
            auto corrections = compute_corrections(level,ot,current_seeds_,current_bits);            
            // std::cout<<"begin broadcast"<<std::endl;
            broadcast_corrections(io,corrections);
            all_corrections_.insert(all_corrections_.end(),corrections.begin(),corrections.end()); // 保存各层纠正字
            // std::cout<<"push back\n";
            apply_corrections(corrections,control_bits,current_seeds_,current_bits);
                // for(int i =0 ; i < current_bits.size();++i){
                //     std::cout<<i<<"\t"<<u128_to_binary(current_seeds_[i])<<"\t"<<static_cast<int>(current_bits[i])<<"\n";
                // }  
        }
    };
void DPFParty::apply_corrections(std::vector<CorrectionWord> &corrections, std::vector<uint8_t>control_bits,std::vector<uint128_t> &current_seeds_,std::vector<uint8_t>&current_bits){
        const size_t size = current_seeds_.size() / 3;
        const size_t len = corrections.size();
        assert(current_seeds_.size() == current_bits.size());
        assert(len == msg_blocks_.size());

        for (size_t nums = 0 ; nums < len ; ++nums){
            for (size_t i = nums; i < size; i+=len) {
                if(control_bits[i])
                {
                    current_seeds_[i]= corrections[nums].cw0 ^ current_seeds_[i];
                    current_seeds_[i+size] = corrections[nums].cw1 ^ current_seeds_[i+size];
                    current_seeds_[i+2*size] = corrections[nums].cw2 ^ current_seeds_[i+2*size];
                    current_bits[i] ^= corrections[nums].cb0;
                    current_bits[i+size] ^= corrections[nums].cb1;
                    current_bits[i+size*2] ^= corrections[nums].cb2;
                }
                
            }
        }
        

    };
void DPFParty::broadcast_corrections(NetIO *io,std::vector<CorrectionWord> &corrections){
        uint128_t len = sizeof(CorrectionWord)*corrections.size();
        std::vector<CorrectionWord>  received_corrections(corrections.size()); 
        if(party_id_==1){
            io->send_data(corrections.data(),len);
            
            io->flush();
            io->recv_data(received_corrections.data(),len);
        }
        else{
            io->recv_data(received_corrections.data(),len);
            io->send_data(corrections.data(),len);
            io->flush();
        }
        for(size_t i = 0 ; i < corrections.size() ;++i)
        corrections[i] = corrections[i] ^ received_corrections[i];
        
        
    };

std::vector<uint8_t> DPFParty::expand_seeds(std::vector<uint128_t> &current_seeds_,std::vector<uint8_t> &current_bits) {
    std::vector<uint8_t> control_bits;
    
    const size_t size = current_seeds_.size();
    std::vector<uint128_t> new_seeds(size*3);
    current_bits.resize(size*3);

    for (size_t len = 0 ; len < size ; ++len) {
        control_bits.push_back(current_bits[len]);
        
        PRFEval(prf_keys_->prf_key0, &current_seeds_[len], &new_seeds[len]);
        PRFEval(prf_keys_->prf_key1, &current_seeds_[len], &new_seeds[len+size]);
        PRFEval(prf_keys_->prf_key2, &current_seeds_[len], &new_seeds[len+size*2]);
        current_bits[len] = get_lsb(new_seeds[len]);
        current_bits[len+size] = get_lsb(new_seeds[len+size]);
        current_bits[len+size*2] = get_lsb(new_seeds[len+size*2]);
        
    }
    
    current_seeds_ = std::move(new_seeds);
    return control_bits;
};

std::vector<CorrectionWord> DPFParty::compute_corrections(size_t level,EmpTernaryOt& ot,std::vector<uint128_t> &current_seeds_,std::vector<uint8_t> cb) {
        const size_t msg_len = msg_blocks_.size();
        std::vector<CorrectionWord> corrections(msg_len);
        const uint8_t trit = get_trit(index_, domain_size_, level);
        assert(current_seeds_.size()==cb.size()) ;
        const size_t size = current_seeds_.size() / 3;

        std::vector<CorrectionWord> cw(3*msg_len);
        for( size_t nums = 0 ; nums < msg_len ; ++nums){

            uint128_t s0(0),s1(0),s2(0);
            uint8_t cb0(0),cb1(0),cb2(0);
            
            for (size_t i = nums; i < size; i+=msg_len) {
                s0 ^= current_seeds_[i];
                s1 ^= current_seeds_[i+size];
                s2 ^= current_seeds_[i+2*size];
                cb0 ^= cb[i];
                cb1 ^= cb[i+size];
                cb2 ^= cb[i+2*size];
            }

            uint128_t r;
            
            RAND_bytes(reinterpret_cast<uint8_t*>(&r), sizeof(r));

            if(level ==domain_size_-1) r = msg_blocks_[nums];

            for(u_int8_t j = 0; j < 3 ; ++j){
                const uint128_t index =j*msg_len+nums;
                switch((j+trit) %3){
                    case 0:
                        cw[index].cw0 = r ^ s0;
                        cw[index].cb0 = control_bit ^ cb0;
                        cw[index].cw1 = s1;
                        cw[index].cb1 = cb1;
                        cw[index].cw2 = s2;
                        cw[index].cb2 = cb2;
                        break;
                    case 1:
                        cw[index].cw0 = s0;
                        cw[index].cb0 = cb0;
                        cw[index].cw1 = r ^ s1;
                        cw[index].cb1 = control_bit ^ cb1;
                        cw[index].cw2 = s2;
                        cw[index].cb2 = cb2;
                        break;
                    case 2:
                        cw[index].cw0 = s0;
                        cw[index].cb0 = cb0;
                        cw[index].cw1 = s1;
                        cw[index].cb1 = cb1;
                        cw[index].cw2 = r ^ s2;
                        cw[index].cb2 = control_bit ^ cb2;
                        break;
                    
                }  
            }
        }

       
        
        const uint128_t length =sizeof(CorrectionWord)*msg_len;
        if(party_id_==1){
            
            ot.sendCorrection(cw.data(),length);
            ot.recvCorrection(corrections.data(),trit,length);
            
        }
        else{

            ot.recvCorrection(corrections.data(),trit,length);
            ot.sendCorrection(cw.data(),length);
            
        }
        
        return corrections;

    };

    std::string DPFParty::u128_to_binary(__uint128_t num) {
        if (num == 0) {
            return "0";  // 直接处理零值
        }
    
        std::string bin;
        const int bits = 128;  // 完整输出128位（包含前导零）
        bin.reserve(bits);     // 预分配内存提升效率
    
        // 从最高位（第127位）向最低位（第0位）遍历
        for (int i = bits - 1; i >= 0; --i) {
            __uint128_t mask = (__uint128_t)1 << i;  // 生成掩码
            bin.push_back((num & mask) ? '1' : '0'); // 检查当前位并追加字符
        }
    
        // 若要去除前导零，取消以下注释
        // size_t first_one = bin.find('1');
        // if (first_one != std::string::npos) {
        //     bin = bin.substr(first_one);
        // }
    
        return bin;
    };
    

    
    void DPFParty::apply_batch_corrections(
        std::vector<uint128_t>& new_seeds,          // 待校正的子节点集合
        std::vector<uint8_t>& new_bits,
        const std::vector<uint8_t>& parent_bits, // 父节点集合
        const size_t level       // 本层校正字
    ) {
        const size_t num_parents = parent_bits.size();
        const size_t len = msg_blocks_.size();
        for( size_t nums = 0 ; nums < len; ++nums){

            const auto correction = all_corrections_[level*len+nums];

            for (size_t i = nums; i < num_parents; i+=len) {
                const uint8_t cb = parent_bits[i]; // 获取父节点控制位（如 LSB）
                
                new_seeds[i]     ^= (cb * correction.cw0);
                new_seeds[i + num_parents] ^= (cb * correction.cw1);
                new_seeds[i + 2*num_parents] ^= (cb * correction.cw2);
                new_bits[i] ^= (cb * correction.cb0);
                new_bits[i + num_parents] ^= (cb * correction.cb1);
                new_bits[i + 2*num_parents] ^= (cb * correction.cb2);
            }
        }
        
    }
    void DPFParty::fulldomainevaluation(std::vector<uint128_t>& current_seeds) {
        // 初始化：将初始种子加入工作队列
        current_seeds.insert(current_seeds.end(),initial_seeds_.begin(),initial_seeds_.end());

        std::vector<uint8_t> current_bits;
        for(size_t i = 0 ; i < msg_blocks_.size();++i) 
            current_bits.push_back(control_bit);
        
        assert(current_bits.size() == current_seeds.size());

        // 预分配缓存空间（避免频繁内存分配）
        std::vector<uint128_t> cache_seeds(3 * current_seeds.size());

        std::vector<uint8_t> cache_bits(3 * current_seeds.size());

        // std::cout<<"begin batch eval\n";
        for (size_t level = 0; level < domain_size_; ++level) {


            const size_t current_size = current_seeds.size();
            size_t batch_size;
           
            // 前 LOG_BATCH_SIZE 层小批次，后续层用最大批次
            constexpr size_t LOG_BATCH_SIZE = 6; // 示例值，根据实际调整
            if (level < LOG_BATCH_SIZE) 
                batch_size = pow(3, level) * msg_blocks_.size();
            else 
                batch_size= pow(3, LOG_BATCH_SIZE) * msg_blocks_.size();
                
            
            // 清空缓存，准备批量处理
            cache_seeds.clear();
            cache_bits.clear();
            std::vector<uint128_t> children0, children1, children2;
            children0.resize(current_size);
            children1.resize(current_size);
            children2.resize(current_size);
            // 分批次处理当前层的种子
            for (size_t offset = 0; offset < current_size; offset += batch_size) {
                const size_t current_batch = std::min(batch_size, current_size - offset);
                // 批量生成三个子节点（PRF并行计算）
                
                // 批量调用 PRF 生成子节点（伪代码，需适配实际 PRF 接口）
                PRFBatchEval(prf_keys_->prf_key0, 
                    current_seeds.data() + offset, 
                    children0.data()+offset, 
                    current_batch
                );
                PRFBatchEval(prf_keys_->prf_key1,
                    current_seeds.data() + offset,
                    children1.data()+offset,
                    current_batch
                );
                PRFBatchEval(prf_keys_->prf_key2,
                    current_seeds.data() + offset,
                    children2.data()+offset,
                    current_batch
                );
                    
            }

            // 收集到缓存中（按三叉树顺序）
            for (size_t i = 0; i < current_size; ++i) {
                cache_seeds.push_back(children0[i]);
                cache_bits.push_back(get_lsb(children0[i]));
                
            }
            for (size_t i = 0; i < current_size; ++i) {
                cache_seeds.push_back(children1[i]);
                cache_bits.push_back(get_lsb(children1[i]));
            }
            for (size_t i = 0; i < current_size; ++i) {
                cache_seeds.push_back(children2[i]);
                cache_bits.push_back(get_lsb(children2[i]));
            }

            // 应用本层的校正字（批量处理）

            apply_batch_corrections(
                cache_seeds, 
                cache_bits,
                current_bits, 
                level
            );
            // std::cout<<"apply_batch_corrections\n";
            // 交换当前种子和缓存，复用内存
            current_seeds.swap(cache_seeds);
            current_bits.swap(cache_bits);
        }
       
        // const size_t msg_len = msg_blocks_.size();
        // const size_t num_leaves = std::pow(3,domain_size_);
        // const size_t output_length =  msg_len* num_leaves;
        // current_seeds.reserve(output_length);
        // cache_seeds.reserve(output_length);
        // ExtendOutput(prf_keys_, current_seeds.data(), cache_seeds.data(), num_leaves, output_length);
    }    

    DPFParty& DPFParty::operator=(const DPFParty& other) {
        // 1. 自赋值检查
        if (this == &other) {
            return *this;
        }

        // 2. 释放当前对象的动态资源
        delete prf_keys_;  // 释放原有PRFKeys对象

        // 3. 深拷贝动态资源
        prf_keys_ = new PRFKeys(*other.prf_keys_);  // 假设PRFKeys实现了拷贝构造函数

        // 4. 拷贝非指针成员
        domain_size_ = other.domain_size_;
        index_ = other.index_;
        msg_blocks_ = other.msg_blocks_;  // vector自动深拷贝（元素需支持拷贝）
        all_corrections_ = other.all_corrections_;  // 假设CorrectionWord支持拷贝
        control_bit = other.control_bit;
        initial_seeds_ = other.initial_seeds_;  // vector自动深拷贝

        // 注意：const成员（如party_id_）不可修改，需在构造函数中初始化

        // 5. 返回当前对象引用
        return *this;
    };
    DPFParty::DPFParty() : 
        prf_keys_(nullptr),     // 指针成员初始化为空
        domain_size_(0),        // 数值类型初始化为0
        index_(0), 
        party_id_(0),           // const成员必须在初始化列表中赋值[3,8](@ref)
        control_bit(0)          // 基础类型初始化
    {
        // 构造函数体为空
    };


    size_t DPFParty::get_key_size() {
        size_t key_size = 0;
        key_size += sizeof(control_bit);
        key_size += sizeof(CorrectionWord)*all_corrections_.size();
        key_size += 16*initial_seeds_.size();
        return key_size;
    }